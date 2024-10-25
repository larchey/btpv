// src/auth/authentication.cpp
#include "authentication.hpp"
#include <sstream>
#include <iomanip>
#include <random>
#include <algorithm>
#include <cctype>
#include <regex>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/algorithm/string.hpp>
#include "oath.h" // For TOTP implementation

namespace btpv {
namespace auth {

AuthenticationService::AuthenticationService(
    std::shared_ptr<crypto::EncryptionService> encryption_service,
    std::shared_ptr<db::DatabaseService> db_service)
    : m_encryption_service(encryption_service)
    , m_db_service(db_service) {}

std::pair<bool, std::string> AuthenticationService::login(
    const std::string& username,
    const std::string& password,
    const std::string& mfa_code) {
    
    auto user = m_db_service->getUserByUsername(username);
    if (!user) {
        return {false, ""};
    }

    // Check for account lockout
    auto now = std::chrono::system_clock::now();
    if (user->failed_login_attempts >= MAX_FAILED_ATTEMPTS) {
        auto lockout_time = user->account_locked_until;
        if (lockout_time > now) {
            return {false, ""};
        }
    }

    // Verify password
    if (!m_encryption_service->verifyPassword(password, user->password_hash, user->salt)) {
        // Update failed login attempts
        user->failed_login_attempts++;
        if (user->failed_login_attempts >= MAX_FAILED_ATTEMPTS) {
            user->account_locked_until = now + LOCKOUT_DURATION;
        }
        m_db_service->updateUser(*user);
        return {false, ""};
    }

    // Check MFA if enabled
    if (user->has_mfa_enabled()) {
        if (mfa_code.empty() || !verify_mfa(user->id, mfa_code)) {
            return {false, ""};
        }
    }

    // Reset failed attempts on successful login
    user->failed_login_attempts = 0;
    user->last_login = now;
    m_db_service->updateUser(*user);

    // Generate session token
    std::string token = generate_session_token();
    std::string token_hash = hash_token(token);

    // Store session
    db::Session session;
    session.id = boost::uuids::random_generator()();
    session.user_id = user->id;
    session.token_hash = token_hash;
    session.created_at = now;
    session.expires_at = now + SESSION_DURATION;
    
    if (!m_db_service->createSession(session)) {
        return {false, ""};
    }

    return {true, token};
}

void AuthenticationService::logout(const std::string& token) {
    std::string token_hash = hash_token(token);
    m_db_service->deleteSession(token_hash);
}

bool AuthenticationService::register_user(
    const std::string& username,
    const std::string& password) {
    
    // Validate username
    if (username.empty() || username.length() > 255 ||
        !std::regex_match(username, std::regex("^[a-zA-Z0-9_-]+$"))) {
        return false;
    }

    // Check if username exists
    if (m_db_service->getUserByUsername(username)) {
        return false;
    }

    // Validate password strength
    if (!validate_password_strength(password)) {
        return false;
    }

    // Generate salt and hash password
    std::vector<unsigned char> salt;
    std::string password_hash = m_encryption_service->hashPassword(password, salt);

    // Create user
    models::User user;
    user.id = boost::uuids::random_generator()();
    user.username = username;
    user.password_hash = password_hash;
    user.salt = salt;
    user.created_at = std::chrono::system_clock::now();

    return m_db_service->createUser(user);
}

bool AuthenticationService::update_password(
    const boost::uuids::uuid& user_id,
    const std::string& new_password) {
    
    if (!validate_password_strength(new_password)) {
        return false;
    }

    auto user = m_db_service->getUser(user_id);
    if (!user) {
        return false;
    }

    // Generate new salt and hash password
    std::vector<unsigned char> new_salt;
    std::string new_hash = m_encryption_service->hashPassword(new_password, new_salt);

    user->password_hash = new_hash;
    user->salt = new_salt;

    return m_db_service->updateUser(*user);
}

std::pair<std::string, std::string> AuthenticationService::setup_mfa(
    const boost::uuids::uuid& user_id) {
    
    auto user = m_db_service->getUser(user_id);
    if (!user) {
        return {"", ""};
    }

    // Generate MFA secret
    std::string secret = generate_mfa_secret();
    
    // Generate QR code
    std::string qr_code = generate_mfa_qr_code(user->username, secret);

    // Store MFA secret (but don't activate until verified)
    user->mfa_secret = secret;
    if (!m_db_service->updateUser(*user)) {
        return {"", ""};
    }

    return {secret, qr_code};
}

bool AuthenticationService::verify_mfa(
    const boost::uuids::uuid& user_id,
    const std::string& code) {
    
    auto user = m_db_service->getUser(user_id);
    if (!user || !user->has_mfa_enabled()) {
        return false;
    }

    return verify_totp_code(user->mfa_secret, code);
}

bool AuthenticationService::verify_token(
    const std::string& token,
    boost::uuids::uuid& user_id) {
    
    std::string token_hash = hash_token(token);
    auto session = m_db_service->getSessionByToken(token_hash);
    
    if (!session || session->expires_at <= std::chrono::system_clock::now()) {
        return false;
    }

    user_id = session->user_id;
    return true;
}

void AuthenticationService::cleanup_expired_sessions() {
    m_db_service->deleteExpiredSessions(std::chrono::system_clock::now());
}

// Private helper methods
std::string AuthenticationService::generate_session_token() {
    std::vector<unsigned char> random_bytes(SESSION_TOKEN_LENGTH);
    if (RAND_bytes(random_bytes.data(), SESSION_TOKEN_LENGTH) != 1) {
        throw std::runtime_error("Failed to generate random bytes for session token");
    }

    std::stringstream ss;
    for (auto byte : random_bytes) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return ss.str();
}

std::string AuthenticationService::hash_token(const std::string& token) {
    // Use HMAC-SHA256 for token hashing
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len;
    
    HMAC(EVP_sha256(), token.c_str(), token.length(),
         reinterpret_cast<const unsigned char*>(token.c_str()), token.length(),
         hmac, &hmac_len);

    std::stringstream ss;
    for (unsigned int i = 0; i < hmac_len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hmac[i]);
    }
    return ss.str();
}

bool AuthenticationService::validate_password_strength(const std::string& password) {
    if (password.length() < MIN_PASSWORD_LENGTH) {
        return false;
    }

    bool has_upper = false;
    bool has_lower = false;
    bool has_digit = false;
    bool has_special = false;

    for (char c : password) {
        if (std::isupper(c)) has_upper = true;
        else if (std::islower(c)) has_lower = true;
        else if (std::isdigit(c)) has_digit = true;
        else has_special = true;
    }

    return has_upper && has_lower && has_digit && has_special;
}

std::string AuthenticationService::generate_mfa_secret() {
    std::vector<unsigned char> random_bytes(MFA_SECRET_LENGTH);
    if (RAND_bytes(random_bytes.data(), MFA_SECRET_LENGTH) != 1) {
        throw std::runtime_error("Failed to generate random bytes for MFA secret");
    }

    // Convert to base32
    static const char base32_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string result;
    result.reserve(32);

    int bits_left = 0;
    int current_byte = 0;

    for (unsigned char byte : random_bytes) {
        current_byte = (current_byte << 8) | byte;
        bits_left += 8;

        while (bits_left >= 5) {
            result += base32_chars[(current_byte >> (bits_left - 5)) & 0x1F];
            bits_left -= 5;
        }
    }

    if (bits_left > 0) {
        result += base32_chars[(current_byte << (5 - bits_left)) & 0x1F];
    }

    return result;
}

std::string AuthenticationService::generate_mfa_qr_code(
    const std::string& username,
    const std::string& secret) {
    
    // Format the URI according to the Key Uri Format
    // otpauth://totp/Label?secret=SECRET&issuer=Issuer
    std::stringstream uri;
    uri << "otpauth://totp/"
        << username
        << "?secret=" << secret
        << "&issuer=BTPV"
        << "&algorithm=SHA1"
        << "&digits=6"
        << "&period=30";

    // In a real implementation, we would generate a QR code here
    // For now, we'll just return the URI
    return uri.str();
}

bool AuthenticationService::verify_totp_code(
    const std::string& secret,
    const std::string& code) {
    
    if (code.length() != 6 || !std::all_of(code.begin(), code.end(), ::isdigit)) {
        return false;
    }

    try {
        // Get current time
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

        // Check codes for current time window and adjacent windows
        for (int offset = -1; offset <= 1; ++offset) {
            std::string expected_code = oath_totp(
                secret,
                (time / 30) + offset,  // 30-second window
                6,                     // 6 digits
                "sha1");              // SHA1 algorithm

            if (code == expected_code) {
                return true;
            }
        }
    }
    catch (const std::exception&) {
        return false;
    }

    return false;
}

} // namespace auth
} // namespace btpv