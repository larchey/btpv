// src/backend/utils/config.hpp
#pragma once

#include <string>
#include <memory>
#include <boost/property_tree/ptree.hpp>

namespace btpv {
namespace utils {

class ConfigurationService {
public:
    static ConfigurationService& instance();

    void load(const std::string& config_path);
    void reload();

    // Database settings
    std::string get_db_connection_string() const;
    int get_db_max_connections() const;
    int get_db_idle_timeout() const;
    int get_db_connection_timeout() const;

    // Server settings
    std::string get_server_address() const;
    int get_server_port() const;
    int get_worker_threads() const;
    int get_request_timeout() const;

    // Security settings
    std::string get_tls_cert_path() const;
    std::string get_tls_key_path() const;
    int get_min_password_length() const;
    bool get_require_special_chars() const;
    bool get_require_numbers() const;
    bool get_require_uppercase() const;
    bool get_require_lowercase() const;
    int get_max_password_age() const;
    int get_password_history_size() const;
    int get_session_timeout() const;
    int get_max_failed_attempts() const;
    int get_lockout_duration() const;

    // MFA settings
    bool get_mfa_required() const;
    std::string get_totp_issuer() const;
    int get_totp_digits() const;
    int get_totp_period() const;
    int get_backup_codes_count() const;

    // Encryption settings
    int get_key_derivation_iterations() const;
    int get_key_length() const;
    int get_key_rotation_period() const;

    // Rate limiting
    int get_login_rate_limit() const;
    int get_login_rate_window() const;
    int get_api_rate_limit() const;
    int get_api_rate_window() const;

private:
    ConfigurationService() = default;
    ConfigurationService(const ConfigurationService&) = delete;
    ConfigurationService& operator=(const ConfigurationService&) = delete;

    boost::property_tree::ptree m_config;
    std::string m_config_path;

    template<typename T>
    T get_value(const std::string& path, const T& default_value) const;
};

} // namespace utils
} // namespace btpv