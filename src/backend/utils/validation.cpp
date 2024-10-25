// src/backend/utils/validation.cpp
#include "validation.hpp"
#include <regex>
#include <algorithm>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/string_generator.hpp>
#include <boost/algorithm/string.hpp>

namespace btpv {
namespace utils {

bool ValidationService::validate_username(const std::string& username, std::string& error) {
    if (!check_length(username, 3, 32, error)) {
        error = "Username must be between 3 and 32 characters";
        return false;
    }

    // Username can only contain alphanumeric characters, underscore, and hyphen
    static const std::regex username_regex("^[a-zA-Z0-9_-]+$");
    if (!std::regex_match(username, username_regex)) {
        error = "Username can only contain letters, numbers, underscore, and hyphen";
        return false;
    }

    return true;
}

bool ValidationService::validate_password(const std::string& password, std::string& error) {
    if (!check_length(password, 12, 128, error)) {
        error = "Password must be between 12 and 128 characters";
        return false;
    }

    bool has_upper = std::any_of(password.begin(), password.end(), ::isupper);
    bool has_lower = std::any_of(password.begin(), password.end(), ::islower);
    bool has_digit = std::any_of(password.begin(), password.end(), ::isdigit);
    bool has_special = std::any_of(password.begin(), password.end(), 
        [](char c) { return !::isalnum(c); });

    if (!has_upper || !has_lower || !has_digit || !has_special) {
        error = "Password must contain at least one uppercase letter, lowercase letter, "
               "number, and special character";
        return false;
    }

    return true;
}

bool ValidationService::validate_mfa_code(const std::string& code, std::string& error) {
    if (code.length() != 6) {
        error = "MFA code must be exactly 6 digits";
        return false;
    }

    if (!std::all_of(code.begin(), code.end(), ::isdigit)) {
        error = "MFA code must contain only digits";
        return false;
    }

    return true;
}

bool ValidationService::validate_group_name(const std::string& name, std::string& error) {
    if (!check_length(name, 1, 64, error)) {
        error = "Group name must be between 1 and 64 characters";
        return false;
    }

    // Allow alphanumeric characters, spaces, and common punctuation
    static const std::regex group_name_regex("^[a-zA-Z0-9\\s\\-_.,!&()]+$");
    if (!std::regex_match(name, group_name_regex)) {
        error = "Group name contains invalid characters";
        return false;
    }

    return true;
}

bool ValidationService::validate_access_level(int level, std::string& error) {
    if (level < 0 || level > 2) {
        error = "Invalid access level. Must be 0 (read), 1 (write), or 2 (admin)";
        return false;
    }
    return true;
}

bool ValidationService::validate_password_title(const std::string& title, std::string& error) {
    if (!check_length(title, 1, 255, error)) {
        error = "Password title must be between 1 and 255 characters";
        return false;
    }

    // Allow most printable characters but restrict potentially dangerous ones
    static const std::regex title_regex("^[^<>&\"'\\\\]+$");
    if (!std::regex_match(title, title_regex)) {
        error = "Password title contains invalid characters";
        return false;
    }

    return true;
}

bool ValidationService::validate_password_value(const std::string& password, std::string& error) {
    if (!check_length(password, 1, 4096, error)) {
        error = "Password value must be between 1 and 4096 characters";
        return false;
    }

    // Check for non-printable characters
    if (std::any_of(password.begin(), password.end(), 
        [](char c) { return !std::isprint(static_cast<unsigned char>(c)); })) {
        error = "Password contains invalid characters";
        return false;
    }

    return true;
}

bool ValidationService::validate_url(const std::string& url, std::string& error) {
    if (url.empty()) {
        return true;  // URL is optional
    }

    if (!check_length(url, 1, 2048, error)) {
        error = "URL must be between 1 and 2048 characters";
        return false;
    }

    // Basic URL validation - for more comprehensive validation, consider using a URL parsing library
    static const std::regex url_regex(
        R"(^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$)",
        std::regex::icase
    );

    if (!std::regex_match(url, url_regex)) {
        error = "Invalid URL format";
        return false;
    }

    return true;
}

bool ValidationService::validate_uuid(const std::string& uuid_str, std::string& error) {
    static const std::regex uuid_regex(
        "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    );

    if (!std::regex_match(uuid_str, uuid_regex)) {
        error = "Invalid UUID format";
        return false;
    }

    return true;
}

std::optional<boost::uuids::uuid> ValidationService::parse_uuid(const std::string& uuid_str) {
    try {
        boost::uuids::string_generator gen;
        return gen(uuid_str);
    }
    catch (const std::exception&) {
        return std::nullopt;
    }
}

bool ValidationService::validate_auth_token(const std::string& token, std::string& error) {
    if (!check_length(token, 32, 512, error)) {
        error = "Invalid token length";
        return false;
    }

    // Token should be a hex string
    static const std::regex token_regex("^[0-9a-fA-F]+$");
    if (!std::regex_match(token, token_regex)) {
        error = "Invalid token format";
        return false;
    }

    return true;
}

bool ValidationService::validate_session_token(const std::string& token, std::string& error) {
    return validate_auth_token(token, error);  // Same validation rules as auth token
}

bool ValidationService::check_length(const std::string& str, size_t min, size_t max, std::string& error) {
    if (str.length() < min || str.length() > max) {
        error = "Length must be between " + std::to_string(min) + 
                " and " + std::to_string(max) + " characters";
        return false;
    }
    return true;
}

bool ValidationService::check_pattern(const std::string& str, const std::string& pattern, std::string& error) {
    try {
        std::regex regex(pattern);
        if (!std::regex_match(str, regex)) {
            error = "Invalid format";
            return false;
        }
        return true;
    }
    catch (const std::regex_error&) {
        error = "Invalid pattern";
        return false;
    }
}

} // namespace utils
} // namespace btpv