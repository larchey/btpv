// src/backend/utils/logging.cpp
#include "logging.hpp"
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sinks/text_file_backend.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/core/null_deleter.hpp>
#include <boost/make_shared.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/uuid/uuid_io.hpp>

namespace btpv {
namespace utils {

namespace logging = boost::log;
namespace sinks = boost::log::sinks;
namespace keywords = boost::log::keywords;
namespace expr = boost::log::expressions;

LoggingService& LoggingService::instance() {
    static LoggingService instance;
    return instance;
}

void LoggingService::init(const std::string& log_level, const std::string& log_file) {
    // Add common attributes
    logging::add_common_attributes();

    // Setup console logging
    setup_console_logging();

    // Setup file logging
    setup_file_logging(log_file);

    // Set log level
    set_log_level(log_level);
}

void LoggingService::setup_file_logging(const std::string& log_file) {
    auto file_sink = logging::add_file_log(
        keywords::file_name = log_file,
        keywords::rotation_size = 10 * 1024 * 1024, // 10MB
        keywords::time_based_rotation = sinks::file::rotation_at_time_point(0, 0, 0),
        keywords::format = (
            expr::stream
                << "[" << expr::format_date_time<boost::posix_time::ptime>("TimeStamp", "%Y-%m-%d %H:%M:%S.%f")
                << "] [" << expr::attr<logging::trivial::severity_level>("Severity")
                << "] [" << expr::attr<std::string>("Component")
                << "] " << expr::smessage
        )
    );

    file_sink->locked_backend()->auto_flush(true);
}

void LoggingService::setup_console_logging() {
    auto console_sink = logging::add_console_log(
        std::cout,
        keywords::format = (
            expr::stream
                << "[" << expr::format_date_time<boost::posix_time::ptime>("TimeStamp", "%Y-%m-%d %H:%M:%S")
                << "] [" << expr::attr<logging::trivial::severity_level>("Severity")
                << "] " << expr::smessage
        )
    );
}

void LoggingService::set_log_level(const std::string& level) {
    auto log_level = logging::trivial::info;

    if (level == "trace")
        log_level = logging::trivial::trace;
    else if (level == "debug")
        log_level = logging::trivial::debug;
    else if (level == "info")
        log_level = logging::trivial::info;
    else if (level == "warning")
        log_level = logging::trivial::warning;
    else if (level == "error")
        log_level = logging::trivial::error;
    else if (level == "fatal")
        log_level = logging::trivial::fatal;

    logging::core::get()->set_filter(
        logging::trivial::severity >= log_level
    );
}

std::string LoggingService::format_log_message(
    const std::string& component,
    const std::string& message,
    const std::string& additional_info) {
    
    std::stringstream ss;
    ss << "[" << component << "] " << message;
    if (!additional_info.empty()) {
        ss << " | " << additional_info;
    }
    return ss.str();
}

// System events
void LoggingService::log_startup(const std::string& version, const std::string& config_path) {
    BOOST_LOG_TRIVIAL(info) << format_log_message("System", 
        "Starting BTPV Server", 
        "Version: " + version + ", Config: " + config_path);
}

void LoggingService::log_shutdown(const std::string& reason) {
    BOOST_LOG_TRIVIAL(info) << format_log_message("System", 
        "Shutting down BTPV Server", 
        "Reason: " + reason);
}

void LoggingService::log_config_reload() {
    BOOST_LOG_TRIVIAL(info) << format_log_message("System", 
        "Configuration reloaded");
}

// Authentication events
void LoggingService::log_login_attempt(
    const std::string& username, 
    bool success, 
    const std::string& ip_address) {
    
    auto level = success ? logging::trivial::info : logging::trivial::warning;
    BOOST_LOG_TRIVIAL(level) << format_log_message("Auth",
        "Login attempt: " + username,
        "Success: " + std::string(success ? "true" : "false") + ", IP: " + ip_address);
}

void LoggingService::log_logout(const boost::uuids::uuid& user_id) {
    BOOST_LOG_TRIVIAL(info) << format_log_message("Auth",
        "User logout",
        "User ID: " + boost::uuids::to_string(user_id));
}

void LoggingService::log_failed_login(const std::string& username, const std::string& reason) {
    BOOST_LOG_TRIVIAL(warning) << format_log_message("Auth",
        "Failed login: " + username,
        "Reason: " + reason);
}

void LoggingService::log_mfa_attempt(const boost::uuids::uuid& user_id, bool success) {
    auto level = success ? logging::trivial::info : logging::trivial::warning;
    BOOST_LOG_TRIVIAL(level) << format_log_message("Auth",
        "MFA verification attempt",
        "User ID: " + boost::uuids::to_string(user_id) + 
        ", Success: " + std::string(success ? "true" : "false"));
}

// Access events
void LoggingService::log_group_access(
    const boost::uuids::uuid& user_id,
    const boost::uuids::uuid& group_id,
    const std::string& action) {
    
    BOOST_LOG_TRIVIAL(info) << format_log_message("Access",
        "Group access: " + action,
        "User ID: " + boost::uuids::to_string(user_id) + 
        ", Group ID: " + boost::uuids::to_string(group_id));
}

void LoggingService::log_password_access(
    const boost::uuids::uuid& user_id,
    const boost::uuids::uuid& password_id,
    const std::string& action) {
    
    BOOST_LOG_TRIVIAL(info) << format_log_message("Access",
        "Password access: " + action,
        "User ID: " + boost::uuids::to_string(user_id) + 
        ", Password ID: " + boost::uuids::to_string(password_id));
}

// Error events
void LoggingService::log_error(
    const std::string& component,
    const std::string& message,
    const std::string& stack_trace) {
    
    BOOST_LOG_TRIVIAL(error) << format_log_message(component,
        "Error: " + message,
        stack_trace);
}

void LoggingService::log_security_event(
    const std::string& event_type,
    const std::string& description,
    const std::string& ip_address) {
    
    BOOST_LOG_TRIVIAL(warning) << format_log_message("Security",
        event_type,
        "Description: " + description + ", IP: " + ip_address);
}

// Debug/Trace events
void LoggingService::log_debug(const std::string& component, const std::string& message) {
    BOOST_LOG_TRIVIAL(debug) << format_log_message(component, message);
}

void LoggingService::log_trace(const std::string& component, const std::string& message) {
    BOOST_LOG_TRIVIAL(trace) << format_log_message(component, message);
}

} // namespace utils
} // namespace btpv