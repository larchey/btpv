
// src/crypto/encryption.cpp
#include "encryption.hpp"
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <argon2.h>

namespace btpv {
namespace crypto {

EncryptionService::EncryptionService() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

EncryptionService::~EncryptionService() {
    EVP_cleanup();
    ERR_free_strings();
}

std::vector<unsigned char> EncryptionService::generateKey() const {
    std::vector<unsigned char> key(KEY_SIZE);
    if (RAND_bytes(key.data(), KEY_SIZE) != 1) {
        handleOpenSSLError("Key generation failed");
    }
    return key;
}

std::vector<unsigned char> EncryptionService::generateIV() const {
    std::vector<unsigned char> iv(IV_SIZE);
    if (RAND_bytes(iv.data(), IV_SIZE) != 1) {
        handleOpenSSLError("IV generation failed");
    }
    return iv;
}

std::vector<unsigned char> EncryptionService::deriveKey(
    const std::string& password,
    const std::vector<unsigned char>& salt) const {
    
    std::vector<unsigned char> derived_key(KEY_SIZE);
    
    // Argon2id parameters (compliant with DOD requirements)
    uint32_t t_cost = 3;            // Number of iterations
    uint32_t m_cost = 65536;        // Memory usage in KiB
    uint32_t parallelism = 4;       // Number of threads
    
    int result = argon2id_hash_raw(
        t_cost,
        m_cost,
        parallelism,
        password.c_str(),
        password.length(),
        salt.data(),
        salt.size(),
        derived_key.data(),
        KEY_SIZE
    );
    
    if (result != ARGON2_OK) {
        throw std::runtime_error("Key derivation failed: " + std::string(argon2_error_message(result)));
    }
    
    return derived_key;
}

EncryptionService::EncryptedData EncryptionService::encrypt(
    const std::string& plaintext,
    const std::vector<unsigned char>& key) {
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleOpenSSLError("Context creation failed");
    }
    
    EncryptedData result;
    result.iv = generateIV();
    result.tag.resize(TAG_SIZE);
    
    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), result.iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        handleOpenSSLError("Encryption initialization failed");
    }
    
    // Encrypt the plaintext
    std::vector<unsigned char> ciphertext(plaintext.length() + EVP_MAX_BLOCK_LENGTH);
    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                         reinterpret_cast<const unsigned char*>(plaintext.data()),
                         plaintext.length()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        handleOpenSSLError("Encryption failed");
    }
    
    int ciphertext_len = len;
    
    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        handleOpenSSLError("Encryption finalization failed");
    }
    
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);
    
    // Get the tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, result.tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        handleOpenSSLError("Tag generation failed");
    }
    
    result.ciphertext = std::move(ciphertext);
    EVP_CIPHER_CTX_free(ctx);
    
    return result;
}

std::string EncryptionService::decrypt(
    const EncryptedData& data,
    const std::vector<unsigned char>& key) {
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleOpenSSLError("Context creation failed");
    }
    
    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), data.iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        handleOpenSSLError("Decryption initialization failed");
    }
    
    // Decrypt the ciphertext
    std::vector<unsigned char> plaintext(data.ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
    int len;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                         data.ciphertext.data(),
                         data.ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        handleOpenSSLError("Decryption failed");
    }
    
    int plaintext_len = len;
    
    // Set expected tag value
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, 
                           const_cast<unsigned char*>(data.tag.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        handleOpenSSLError("Tag verification failed");
    }
    
    // Finalize decryption
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        handleOpenSSLError("Decryption finalization failed");
    }
    
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    
    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
}

void EncryptionService::handleOpenSSLError(const std::string& operation) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    throw std::runtime_error(operation + ": " + err_buf);
}

std::string EncryptionService::hashPassword(
    const std::string& password,
    std::vector<unsigned char>& salt) {
    
    // Generate salt if not provided
    if (salt.empty()) {
        salt.resize(16);
        if (RAND_bytes(salt.data(), salt.size()) != 1) {
            handleOpenSSLError("Salt generation failed");
        }
    }
    
    // Use Argon2id for password hashing
    std::vector<unsigned char> hash(32);
    uint32_t t_cost = 3;
    uint32_t m_cost = 65536;
    uint32_t parallelism = 4;
    
    int result = argon2id_hash_raw(
        t_cost,
        m_cost,
        parallelism,
        password.c_str(),
        password.length(),
        salt.data(),
        salt.size(),
        hash.data(),
        hash.size()
    );
    
    if (result != ARGON2_OK) {
        throw std::runtime_error("Password hashing failed: " + std::string(argon2_error_message(result)));
    }
    
    // Convert hash to hex string
    std::stringstream ss;
    for (const auto& byte : hash) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    
    return ss.str();
}

bool EncryptionService::verifyPassword(
    const std::string& password,
    const std::string& hash,
    const std::vector<unsigned char>& salt) {
    
    std::string computed_hash = hashPassword(password, salt);
    return computed_hash == hash;
}

} // namespace crypto
} // namespace btpv