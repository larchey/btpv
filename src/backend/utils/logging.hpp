// src/backend/utils/logging.hpp
#pragma once

#include <string>
#include <boost/log/trivial.hpp>
#include <boost/uuid/uuid.hpp>

namespace btpv {
namespace utils {

class LoggingService {
public:
    static LoggingService& instance();

    void init(const std::string& log_level, const std::string& log_file);

    // System events
    void log_startup(const std::string& version, const std::string& config_path);
    void log_shutdown(const std::string& reason);
    void log_config_reload();

    // Authentication events
    void log_login_attempt(const std::string& username, bool success, 
                          const std::string& ip_address);
    void log_logout(const boost::uuids::uuid& user_id);
    void log_failed_login(const std::string& username, const std::string& reason);
    void log_mfa_attempt(const boost::uuids::uuid& user_id, bool success);

    // Access events
    void log_group_access(const boost::uuids::uuid& user_id, 
                         const boost::uuids::uuid& group_id,
                         const std::string& action);
    void log_password_access(const boost::uuids::uuid& user_id,
                           const boost::uuids::uuid& password_id,
                           const std::string& action);

    // Error events
    void log_error(const std::string& component, const std::string& message,
                  const std::string& stack_trace = "");
    void log_security_event(const std::string& event_type, 
                          const std::string& description,
                          const std::string& ip_address);

    // Debug/Trace events
    void log_debug(const std::string& component, const std::string& message);
    void log_trace(const std::string& component, const std::string& message);

private:
    LoggingService() = default;
    LoggingService(const LoggingService&) = delete;
    LoggingService& operator=(const LoggingService&) = delete;

    void setup_file_logging(const std::string& log_file);
    void setup_console_logging();
    void set_log_level(const std::string& level);
    std::string format_log_message(const std::string& component,
                                 const std::string& message,
                                 const std::string& additional_info = "");
};

// Convenience macros for logging
#define LOG_INFO(component, message) \
    BOOST_LOG_TRIVIAL(info) << "[" << component << "] " << message

#define LOG_ERROR(component, message) \
    BOOST_LOG_TRIVIAL(error) << "[" << component << "] " << message

#define LOG_WARNING(component, message) \
    BOOST_LOG_TRIVIAL(warning) << "[" << component << "] " << message

#define LOG_DEBUG(component, message) \
    BOOST_LOG_TRIVIAL(debug) << "[" << component << "] " << message

#define LOG_TRACE(component, message) \
    BOOST_LOG_TRIVIAL(trace) << "[" << component << "] " << message

} // namespace utils
} // namespace btpv