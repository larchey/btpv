// src/auth/authentication.hpp
#pragma once

#include <string>
#include <memory>
#include <vector>
#include <chrono>
#include <optional>
#include <utility>
#include <boost/uuid/uuid.hpp>
#include "../crypto/encryption.hpp"
#include "../db/database.hpp"

namespace btpv {
namespace auth {

class AuthenticationService {
public:
    AuthenticationService(
        std::shared_ptr<crypto::EncryptionService> encryption_service,
        std::shared_ptr<db::DatabaseService> db_service);
    
    // User authentication
    std::pair<bool, std::string> login(
        const std::string& username,
        const std::string& password,
        const std::string& mfa_code = "");
    
    void logout(const std::string& token);
    
    bool register_user(
        const std::string& username,
        const std::string& password);
    
    bool update_password(
        const boost::uuids::uuid& user_id,
        const std::string& new_password);
    
    // MFA operations
    std::pair<std::string, std::string> setup_mfa(const boost::uuids::uuid& user_id);
    bool verify_mfa(const boost::uuids::uuid& user_id, const std::string& code);
    
    // Token management
    bool verify_token(const std::string& token, boost::uuids::uuid& user_id);
    void cleanup_expired_sessions();

private:
    std::shared_ptr<crypto::EncryptionService> m_encryption_service;
    std::shared_ptr<db::DatabaseService> m_db_service;

    // Session management
    std::string generate_session_token();
    std::string hash_token(const std::string& token);
    
    // Password validation
    bool validate_password_strength(const std::string& password);
    
    // MFA helpers
    std::string generate_mfa_secret();
    std::string generate_mfa_qr_code(
        const std::string& username,
        const std::string& secret);
    bool verify_totp_code(
        const std::string& secret,
        const std::string& code);

    // Constants
    static constexpr size_t MIN_PASSWORD_LENGTH = 12;
    static constexpr size_t SESSION_TOKEN_LENGTH = 32;
    static constexpr size_t MFA_SECRET_LENGTH = 20;
    static constexpr int MAX_FAILED_ATTEMPTS = 5;
    static constexpr std::chrono::minutes LOCKOUT_DURATION{15};
    static constexpr std::chrono::hours SESSION_DURATION{24};
};

} // namespace auth
} // namespace btpv