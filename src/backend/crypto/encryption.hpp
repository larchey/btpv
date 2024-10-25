// src/crypto/encryption.hpp
#pragma once

#include <string>
#include <vector>
#include <memory>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>

namespace btpv {
namespace crypto {

class EncryptionService {
public:
    static constexpr size_t KEY_SIZE = 32;  // 256 bits
    static constexpr size_t IV_SIZE = 12;   // 96 bits for GCM
    static constexpr size_t TAG_SIZE = 16;  // 128 bits for GCM auth tag

    struct EncryptedData {
        std::vector<unsigned char> ciphertext;
        std::vector<unsigned char> iv;
        std::vector<unsigned char> tag;
    };

    EncryptionService();
    ~EncryptionService();

    // Key management
    std::vector<unsigned char> generateKey() const;
    std::vector<unsigned char> deriveKey(const std::string& password, const std::vector<unsigned char>& salt) const;
    
    // Encryption/Decryption
    EncryptedData encrypt(const std::string& plaintext, const std::vector<unsigned char>& key);
    std::string decrypt(const EncryptedData& data, const std::vector<unsigned char>& key);

    // Password hashing
    std::string hashPassword(const std::string& password, std::vector<unsigned char>& salt);
    bool verifyPassword(const std::string& password, const std::string& hash, const std::vector<unsigned char>& salt);

private:
    std::vector<unsigned char> generateIV() const;
    void handleOpenSSLError(const std::string& operation);
};

} // namespace crypto
} // namespace btpv