// src/backend/utils/validation.hpp
#pragma once

#include <string>
#include <vector>
#include <optional>
#include <boost/uuid/uuid.hpp>

namespace btpv {
namespace utils {

class ValidationService {
public:
    // User validation
    static bool validate_username(const std::string& username, std::string& error);
    static bool validate_password(const std::string& password, std::string& error);
    static bool validate_mfa_code(const std::string& code, std::string& error);

    // Group validation
    static bool validate_group_name(const std::string& name, std::string& error);
    static bool validate_access_level(int level, std::string& error);

    // Password validation
    static bool validate_password_title(const std::string& title, std::string& error);
    static bool validate_password_value(const std::string& password, std::string& error);
    static bool validate_url(const std::string& url, std::string& error);

    // UUID validation
    static bool validate_uuid(const std::string& uuid_str, std::string& error);
    static std::optional<boost::uuids::uuid> parse_uuid(const std::string& uuid_str);

    // Token validation
    static bool validate_auth_token(const std::string& token, std::string& error);
    static bool validate_session_token(const std::string& token, std::string& error);

private:
    static bool check_length(const std::string& str, size_t min, size_t max, std::string& error);
    static bool check_pattern(const std::string& str, const std::string& pattern, std::string& error);
};

} // namespace utils
} // namespace btpv