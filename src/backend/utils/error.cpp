// src/backend/utils/error.cpp
#include "error.hpp"
#include <sstream>
#include <boost/stacktrace.hpp>
#include "logging.hpp"

namespace btpv {
namespace utils {

namespace {
    // Convert stacktrace to string
    std::string get_stacktrace() {
        std::stringstream ss;
        ss << boost::stacktrace::stacktrace();
        return ss.str();
    }

    // Get error message based on error code
    std::string get_error_message(ErrorCode code) {
        switch (code) {
            // Authentication errors
            case ErrorCode::INVALID_CREDENTIALS:
                return "Invalid username or password";
            case ErrorCode::ACCOUNT_LOCKED:
                return "Account is temporarily locked due to too many failed attempts";
            case ErrorCode::INVALID_TOKEN:
                return "Invalid or expired authentication token";
            case ErrorCode::MFA_REQUIRED:
                return "Multi-factor authentication is required";
            case ErrorCode::INVALID_MFA_CODE:
                return "Invalid MFA code";

            // Authorization errors
            case ErrorCode::INSUFFICIENT_PERMISSIONS:
                return "Insufficient permissions to perform this action";
            case ErrorCode::INVALID_ACCESS_LEVEL:
                return "Invalid access level specified";

            // Validation errors
            case ErrorCode::INVALID_USERNAME:
                return "Invalid username format";
            case ErrorCode::INVALID_PASSWORD:
                return "Password does not meet security requirements";
            case ErrorCode::INVALID_GROUP_NAME:
                return "Invalid group name";
            case ErrorCode::INVALID_UUID:
                return "Invalid UUID format";

            // Database errors
            case ErrorCode::DATABASE_CONNECTION_ERROR:
                return "Failed to connect to database";
            case ErrorCode::DATABASE_QUERY_ERROR:
                return "Database query failed";
            case ErrorCode::UNIQUE_CONSTRAINT_VIOLATION:
                return "Record already exists";

            // Resource errors
            case ErrorCode::USER_NOT_FOUND:
                return "User not found";
            case ErrorCode::GROUP_NOT_FOUND:
                return "Group not found";
            case ErrorCode::PASSWORD_NOT_FOUND:
                return "Password not found";

            // Rate limiting errors
            case ErrorCode::TOO_MANY_REQUESTS:
                return "Too many requests, please try again later";
            case ErrorCode::TOO_MANY_LOGIN_ATTEMPTS:
                return "Too many login attempts, please try again later";

            // Encryption errors
            case ErrorCode::ENCRYPTION_FAILED:
                return "Failed to encrypt data";
            case ErrorCode::DECRYPTION_FAILED:
                return "Failed to decrypt data";
            case ErrorCode::KEY_DERIVATION_FAILED:
                return "Failed to derive encryption key";

            default:
                return "Unknown error";
        }
    }
}

// Utility functions for error handling
void throw_error(ErrorCode code, const std::string& additional_info = "") {
    std::string message = get_error_message(code);
    if (!additional_info.empty()) {
        message += ": " + additional_info;
    }

    // Log the error with stack trace
    LoggingService::instance().log_error(
        "Error",
        message,
        get_stacktrace()
    );

    switch (static_cast<int>(code) / 1000) {
        case 1:
            throw AuthenticationError(message);
        case 2:
            throw AuthorizationError(message);
        case 3:
            throw ValidationError(message);
        case 4:
            throw DatabaseError(message);
        case 5:
            throw NotFoundError(message);
        case 6:
            throw RateLimitError(message);
        case 7:
            throw EncryptionError(message);
        default:
            throw BtpvException(message);
    }
}

// Create error response with optional HTTP status code
std::pair<std::string, int> create_error_response(
    ErrorCode code,
    const std::string& additional_info = "") {
    
    std::string message = get_error_message(code);
    if (!additional_info.empty()) {
        message += ": " + additional_info;
    }

    int http_status;
    switch (static_cast<int>(code) / 1000) {
        case 1:
            http_status = 401; // Authentication errors
            break;
        case 2:
            http_status = 403; // Authorization errors
            break;
        case 3:
            http_status = 400; // Validation errors
            break;
        case 4:
            http_status = 500; // Database errors
            break;
        case 5:
            http_status = 404; // Not found errors
            break;
        case 6:
            http_status = 429; // Rate limiting errors
            break;
        case 7:
            http_status = 500; // Encryption errors
            break;
        default:
            http_status = 500; // Internal server error
    }

    return {message, http_status};
}

// Exception handlers
void handle_exception(const std::function<void()>& func) {
    try {
        func();
    } catch (const BtpvException& e) {
        LoggingService::instance().log_error(
            "Exception",
            e.what(),
            get_stacktrace()
        );
        throw; // Re-throw the exception
    } catch (const std::exception& e) {
        LoggingService::instance().log_error(
            "UnhandledException",
            e.what(),
            get_stacktrace()
        );
        throw BtpvException(std::string("Unhandled error: ") + e.what());
    }
}

// Transaction handler
template<typename T>
T handle_transaction(const std::function<T(db::DatabaseService::Transaction&)>& func,
                    db::DatabaseService& db_service) {
    auto txn = db_service.beginTransaction();
    try {
        T result = func(txn);
        txn.commit();
        return result;
    } catch (...) {
        txn.rollback();
        throw;
    }
}

// Validation helper
void validate_or_throw(bool condition, ErrorCode error_code, const std::string& additional_info = "") {
    if (!condition) {
        throw_error(error_code, additional_info);
    }
}

// Rate limiting helper
class RateLimiter {
public:
    static void check_rate_limit(const std::string& key, int max_requests, int window_seconds) {
        // Implementation would go here - this is just a placeholder
        // In a real implementation, this would use Redis or a similar system
        // to track request counts and enforce rate limits
        throw_error(ErrorCode::TOO_MANY_REQUESTS, "Rate limit exceeded for " + key);
    }
};

} // namespace utils
} // namespace btpv