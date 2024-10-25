// src/backend/utils/error.hpp
#pragma once

#include <string>
#include <stdexcept>

namespace btpv {
namespace utils {

// Base exception class for all BTPV exceptions
class BtpvException : public std::runtime_error {
public:
    explicit BtpvException(const std::string& message) 
        : std::runtime_error(message) {}

    virtual int error_code() const = 0;
};

// Authentication related errors
class AuthenticationError : public BtpvException {
public:
    explicit AuthenticationError(const std::string& message) 
        : BtpvException(message) {}

    int error_code() const override { return 401; }
};

// Authorization related errors
class AuthorizationError : public BtpvException {
public:
    explicit AuthorizationError(const std::string& message) 
        : BtpvException(message) {}

    int error_code() const override { return 403; }
};

// Validation errors
class ValidationError : public BtpvException {
public:
    explicit ValidationError(const std::string& message) 
        : BtpvException(message) {}

    int error_code() const override { return 400; }
};

// Database errors
class DatabaseError : public BtpvException {
public:
    explicit DatabaseError(const std::string& message) 
        : BtpvException(message) {}

    int error_code() const override { return 500; }
};

// Resource not found errors
class NotFoundError : public BtpvException {
public:
    explicit NotFoundError(const std::string& message) 
        : BtpvException(message) {}

    int error_code() const override { return 404; }
};

// Rate limiting errors
class RateLimitError : public BtpvException {
public:
    explicit RateLimitError(const std::string& message) 
        : BtpvException(message) {}

    int error_code() const override { return 429; }
};

// Encryption errors
class EncryptionError : public BtpvException {
public:
    explicit EncryptionError(const std::string& message) 
        : BtpvException(message) {}

    int error_code() const override { return 500; }
};

// Error codes for specific scenarios
enum class ErrorCode {
    // Authentication errors (1xxx)
    INVALID_CREDENTIALS = 1001,
    ACCOUNT_LOCKED = 1002,
    INVALID_TOKEN = 1003,
    MFA_REQUIRED = 1004,
    INVALID_MFA_CODE = 1005,

    // Authorization errors (2xxx)
    INSUFFICIENT_PERMISSIONS = 2001,
    INVALID_ACCESS_LEVEL = 2002,

    // Validation errors (3xxx)
    INVALID_USERNAME = 3001,
    INVALID_PASSWORD = 3002,
    INVALID_GROUP_NAME = 3003,
    INVALID_UUID = 3004,

    // Database errors (4xxx)
    DATABASE_CONNECTION_ERROR = 4001,
    DATABASE_QUERY_ERROR = 4002,
    UNIQUE_CONSTRAINT_VIOLATION = 4003,

    // Resource errors (5xxx)
    USER_NOT_FOUND = 5001,
    GROUP_NOT_FOUND = 5002,
    PASSWORD_NOT_FOUND = 5003,

    // Rate limiting errors (6xxx)
    TOO_MANY_REQUESTS = 6001,
    TOO_MANY_LOGIN_ATTEMPTS = 6002,

    // Encryption errors (7xxx)
    ENCRYPTION_FAILED = 7001,
    DECRYPTION_FAILED = 7002,
    KEY_DERIVATION_FAILED = 7003
};

} // namespace utils
} // namespace btpv