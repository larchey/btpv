// src/backend/api/controller.hpp
#pragma once

#include <memory>
#include <cpprest/http_listener.h>
#include <cpprest/json.h>
#include "../crypto/encryption.hpp"
#include "../db/database.hpp"
#include "../auth/authentication.hpp"

namespace btpv {
namespace api {

class ApiController {
public:
    ApiController(const std::string& address, 
                 int port,
                 std::shared_ptr<crypto::EncryptionService> encryption_service,
                 std::shared_ptr<db::DatabaseService> db_service,
                 std::shared_ptr<auth::AuthenticationService> auth_service);
    ~ApiController();

    void start();
    void stop();

private:
    web::http::experimental::listener::http_listener m_listener;
    std::shared_ptr<crypto::EncryptionService> m_encryption_service;
    std::shared_ptr<db::DatabaseService> m_db_service;
    std::shared_ptr<auth::AuthenticationService> m_auth_service;

    // Auth endpoints
    void handle_login(web::http::http_request request);
    void handle_logout(web::http::http_request request);
    void handle_register(web::http::http_request request);
    void handle_mfa_setup(web::http::http_request request);
    void handle_mfa_verify(web::http::http_request request);

    // User endpoints
    void handle_get_user(web::http::http_request request);
    void handle_update_user(web::http::http_request request);

    // Group endpoints
    void handle_create_group(web::http::http_request request);
    void handle_get_groups(web::http::http_request request);
    void handle_update_group(web::http::http_request request);
    void handle_delete_group(web::http::http_request request);
    void handle_add_group_member(web::http::http_request request);
    void handle_remove_group_member(web::http::http_request request);

    // Password endpoints
    void handle_create_password(web::http::http_request request);
    void handle_get_passwords(web::http::http_request request);
    void handle_update_password(web::http::http_request request);
    void handle_delete_password(web::http::http_request request);

    // Helper methods
    void setup_routes();
    web::json::value create_error_response(const std::string& message, int status_code);
    web::json::value create_success_response(const web::json::value& data);
    bool verify_auth_token(const web::http::http_request& request, boost::uuids::uuid& user_id);
    void handle_request(web::http::http_request request, 
                       std::function<void(web::http::http_request&, boost::uuids::uuid)> handler,
                       bool require_auth = true);
};

} // namespace api
} // namespace btpv