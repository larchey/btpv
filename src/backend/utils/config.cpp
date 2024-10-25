// src/backend/utils/config.cpp
#include "config.hpp"
#include <stdexcept>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/algorithm/string.hpp>

namespace btpv {
namespace utils {

ConfigurationService& ConfigurationService::instance() {
    static ConfigurationService instance;
    return instance;
}

void ConfigurationService::load(const std::string& config_path) {
    try {
        boost::property_tree::ini_parser::read_ini(config_path, m_config);
        m_config_path = config_path;
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to load configuration: " + std::string(e.what()));
    }
}

void ConfigurationService::reload() {
    if (m_config_path.empty()) {
        throw std::runtime_error("No configuration file loaded");
    }
    load(m_config_path);
}

template<typename T>
T ConfigurationService::get_value(const std::string& path, const T& default_value) const {
    try {
        return m_config.get<T>(path);
    } catch (const std::exception&) {
        return default_value;
    }
}

// Database settings
std::string ConfigurationService::get_db_connection_string() const {
    return get_value<std::string>("database.connection_string", 
        "host=localhost dbname=btpv user=btpv_user password=secure_password");
}

int ConfigurationService::get_db_max_connections() const {
    return get_value<int>("database.max_connections", 20);
}

int ConfigurationService::get_db_idle_timeout() const {
    return get_value<int>("database.idle_timeout", 300);
}

int ConfigurationService::get_db_connection_timeout() const {
    return get_value<int>("database.connection_timeout", 30);
}

// Server settings
std::string ConfigurationService::get_server_address() const {
    return get_value<std::string>("server.address", "127.0.0.1");
}

int ConfigurationService::get_server_port() const {
    return get_value<int>("server.port", 8443);
}

int ConfigurationService::get_worker_threads() const {
    return get_value<int>("server.worker_threads", 4);
}

int ConfigurationService::get_request_timeout() const {
    return get_value<int>("server.request_timeout", 30);
}

// Security settings
std::string ConfigurationService::get_tls_cert_path() const {
    return get_value<std::string>("security.tls_cert", "/etc/btpv/cert/server.crt");
}

std::string ConfigurationService::get_tls_key_path() const {
    return get_value<std::string>("security.tls_key", "/etc/btpv/cert/server.key");
}

int ConfigurationService::get_min_password_length() const {
    return get_value<int>("security.min_password_length", 12);
}

bool ConfigurationService::get_require_special_chars() const {
    return get_value<bool>("security.require_special_chars", true);
}

bool ConfigurationService::get_require_numbers() const {
    return get_value<bool>("security.require_numbers", true);
}

bool ConfigurationService::get_require_uppercase() const {
    return get_value<bool>("security.require_uppercase", true);
}

bool ConfigurationService::get_require_lowercase() const {
    return get_value<bool>("security.require_lowercase", true);
}

int ConfigurationService::get_max_password_age() const {
    return get_value<int>("security.max_password_age", 90);
}

int ConfigurationService::get_password_history_size() const {
    return get_value<int>("security.password_history", 12);
}

int ConfigurationService::get_session_timeout() const {
    return get_value<int>("security.session_timeout", 3600);
}

int ConfigurationService::get_max_failed_attempts() const {
    return get_value<int>("security.max_failed_attempts", 5);
}

int ConfigurationService::get_lockout_duration() const {
    return get_value<int>("security.lockout_duration", 300);
}

// MFA settings
bool ConfigurationService::get_mfa_required() const {
    return get_value<bool>("mfa.required", true);
}

std::string ConfigurationService::get_totp_issuer() const {
    return get_value<std::string>("mfa.totp_issuer", "BTPV");
}

int ConfigurationService::get_totp_digits() const {
    return get_value<int>("mfa.totp_digits", 6);
}

int ConfigurationService::get_totp_period() const {
    return get_value<int>("mfa.totp_period", 30);
}

int ConfigurationService::get_backup_codes_count() const {
    return get_value<int>("mfa.backup_codes", 8);
}

// Encryption settings
int ConfigurationService::get_key_derivation_iterations() const {
    return get_value<int>("encryption.key_derivation_iterations", 100000);
}

int ConfigurationService::get_key_length() const {
    return get_value<int>("encryption.key_length", 256);
}

int ConfigurationService::get_key_rotation_period() const {
    return get_value<int>("encryption.rotation_period", 90);
}

// Rate limiting
int ConfigurationService::get_login_rate_limit() const {
    return get_value<int>("rate_limiting.login_attempts", 5);
}

int ConfigurationService::get_login_rate_window() const {
    return get_value<int>("rate_limiting.login_window", 300);
}

int ConfigurationService::get_api_rate_limit() const {
    return get_value<int>("rate_limiting.api_requests", 100);
}

int ConfigurationService::get_api_rate_window() const {
    return get_value<int>("rate_limiting.api_window", 60);
}

} // namespace utils
} // namespace btpv