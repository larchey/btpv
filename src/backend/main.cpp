// src/backend/main.cpp
#include <iostream>
#include <string>
#include <memory>
#include <csignal>
#include <boost/program_options.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include "crypto/encryption.hpp"
#include "auth/authentication.hpp"
#include "db/database.hpp"
#include "api/controller.hpp"

namespace {
    volatile std::sig_atomic_t g_running = 1;
    std::unique_ptr<btpv::api::ApiController> g_api_controller;
}

void signal_handler(int signal) {
    g_running = 0;
    if (g_api_controller) {
        g_api_controller->stop();
    }
}

void setup_logging(const std::string& log_level, const std::string& log_file) {
    boost::log::add_file_log(
        boost::log::keywords::file_name = log_file,
        boost::log::keywords::format = "[%TimeStamp%] [%ThreadID%] [%Severity%] %Message%"
    );

    boost::log::add_console_log(
        std::cout,
        boost::log::keywords::format = "[%TimeStamp%] [%ThreadID%] [%Severity%] %Message%"
    );

    // Set log level
    if (log_level == "trace")
        boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::trace);
    else if (log_level == "debug")
        boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::debug);
    else if (log_level == "info")
        boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::info);
    else if (log_level == "warning")
        boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::warning);
    else if (log_level == "error")
        boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::error);
    else if (log_level == "fatal")
        boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::fatal);
}

int main(int argc, char* argv[]) {
    try {
        // Set up command line options
        namespace po = boost::program_options;
        po::options_description desc("Allowed options");
        desc.add_options()
            ("help", "produce help message")
            ("config", po::value<std::string>()->default_value("/etc/btpv/btpv.conf"), "path to configuration file");

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);

        if (vm.count("help")) {
            std::cout << desc << "\n";
            return 1;
        }

        // Load configuration
        boost::property_tree::ptree config;
        boost::property_tree::ini_parser::read_ini(vm["config"].as<std::string>(), config);

        // Set up logging
        setup_logging(
            config.get<std::string>("logging.level", "info"),
            config.get<std::string>("logging.file", "/var/log/btpv/btpv.log")
        );

        BOOST_LOG_TRIVIAL(info) << "Starting BTPV server...";

        // Set up signal handling
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);

        // Initialize services
        auto encryption_service = std::make_shared<btpv::crypto::EncryptionService>();
        
        auto db_service = std::make_shared<btpv::db::DatabaseService>(
            config.get<std::string>("database.connection_string")
        );

        // Run database migrations
        if (!btpv::db::DatabaseMigration::run_migrations(*db_service)) {
            BOOST_LOG_TRIVIAL(fatal) << "Failed to run database migrations";
            return 1;
        }

        auto auth_service = std::make_shared<btpv::auth::AuthenticationService>(
            encryption_service,
            db_service
        );

        // Initialize API controller
        g_api_controller = std::make_unique<btpv::api::ApiController>(
            config.get<std::string>("server.address", "0.0.0.0"),
            config.get<int>("server.port", 8443),
            encryption_service,
            db_service,
            auth_service
        );

        // Start the API server
        g_api_controller->start();
        BOOST_LOG_TRIVIAL(info) << "BTPV server started on " 
                               << config.get<std::string>("server.address", "0.0.0.0")
                               << ":" << config.get<int>("server.port", 8443);

        // Main loop
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            
            // Periodic tasks
            auth_service->cleanup_expired_sessions();
        }

        // Cleanup and shutdown
        g_api_controller->stop();
        BOOST_LOG_TRIVIAL(info) << "BTPV server stopped gracefully";
        return 0;
    }
    catch (const std::exception& e) {
        BOOST_LOG_TRIVIAL(fatal) << "Fatal error: " << e.what();
        return 1;
    }
}