// src/backend/api/controller.cpp
#include "controller.hpp"
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

namespace btpv {
namespace api {

using namespace web::http;
using namespace web::http::experimental::listener;

ApiController::ApiController(
    const std::string& address,
    int port,
    std::shared_ptr<crypto::EncryptionService> encryption_service,
    std::shared_ptr<db::DatabaseService> db_service,
    std::shared_ptr<auth::AuthenticationService> auth_service)
    : m_listener(utility::string_t(U("http://" + address + ":" + std::to_string(port) + "/api/v1")))
    , m_encryption_service(encryption_service)
    , m_db_service(db_service)
    , m_auth_service(auth_service) {
    setup_routes();
}

ApiController::~ApiController() {
    stop();
}

void ApiController::start() {
    m_listener.open().wait();
}

void ApiController::stop() {
    m_listener.close().wait();
}

void ApiController::setup_routes() {
    // Auth routes
    m_listener.support(methods::POST, U("/auth/login"),
        std::bind(&ApiController::handle_login, this, std::placeholders::_1));
    m_listener.support(methods::POST, U("/auth/logout"),
        std::bind(&ApiController::handle_logout, this, std::placeholders::_1));
    m_listener.support(methods::POST, U("/auth/register"),
        std::bind(&ApiController::handle_register, this, std::placeholders::_1));
    m_listener.support(methods::POST, U("/auth/mfa/setup"),
        std::bind(&ApiController::handle_mfa_setup, this, std::placeholders::_1));
    m_listener.support(methods::POST, U("/auth/mfa/verify"),
        std::bind(&ApiController::handle_mfa_verify, this, std::placeholders::_1));

    // User routes
    m_listener.support(methods::GET, U("/user"),
        std::bind(&ApiController::handle_get_user, this, std::placeholders::_1));
    m_listener.support(methods::PUT, U("/user"),
        std::bind(&ApiController::handle_update_user, this, std::placeholders::_1));

    // Group routes
    m_listener.support(methods::POST, U("/groups"),
        std::bind(&ApiController::handle_create_group, this, std::placeholders::_1));
    m_listener.support(methods::GET, U("/groups"),
        std::bind(&ApiController::handle_get_groups, this, std::placeholders::_1));
    m_listener.support(methods::PUT, U("/groups/{id}"),
        std::bind(&ApiController::handle_update_group, this, std::placeholders::_1));
    m_listener.support(methods::DEL, U("/groups/{id}"),
        std::bind(&ApiController::handle_delete_group, this, std::placeholders::_1));
    
    // Group member routes
    m_listener.support(methods::POST, U("/groups/{id}/members"),
        std::bind(&ApiController::handle_add_group_member, this, std::placeholders::_1));
    m_listener.support(methods::DEL, U("/groups/{id}/members/{user_id}"),
        std::bind(&ApiController::handle_remove_group_member, this, std::placeholders::_1));

    // Password routes
    m_listener.support(methods::POST, U("/passwords"),
        std::bind(&ApiController::handle_create_password, this, std::placeholders::_1));
    m_listener.support(methods::GET, U("/groups/{id}/passwords"),
        std::bind(&ApiController::handle_get_passwords, this, std::placeholders::_1));
    m_listener.support(methods::PUT, U("/passwords/{id}"),
        std::bind(&ApiController::handle_update_password, this, std::placeholders::_1));
    m_listener.support(methods::DEL, U("/passwords/{id}"),
        std::bind(&ApiController::handle_delete_password, this, std::placeholders::_1));
}

web::json::value ApiController::create_error_response(const std::string& message, int status_code) {
    web::json::value response;
    response[U("success")] = web::json::value::boolean(false);
    response[U("error")] = web::json::value::string(utility::conversions::to_string_t(message));
    response[U("status")] = web::json::value::number(status_code);
    return response;
}

web::json::value ApiController::create_success_response(const web::json::value& data) {
    web::json::value response;
    response[U("success")] = web::json::value::boolean(true);
    response[U("data")] = data;
    return response;
}

bool ApiController::verify_auth_token(const http_request& request, boost::uuids::uuid& user_id) {
    auto headers = request.headers();
    auto auth_header = headers.find(U("Authorization"));
    
    if (auth_header == headers.end()) {
        return false;
    }

    std::string token = utility::conversions::to_utf8string(auth_header->second);
    if (token.substr(0, 7) != "Bearer ") {
        return false;
    }

    token = token.substr(7);
    return m_auth_service->verify_token(token, user_id);
}

void ApiController::handle_request(
    http_request request,
    std::function<void(http_request&, boost::uuids::uuid)> handler,
    bool require_auth) {
    
    try {
        boost::uuids::uuid user_id;
        
        if (require_auth && !verify_auth_token(request, user_id)) {
            request.reply(status_codes::Unauthorized, 
                create_error_response("Invalid or missing authentication token", 401));
            return;
        }

        handler(request, user_id);
    }
    catch (const std::exception& e) {
        request.reply(status_codes::InternalError,
            create_error_response(e.what(), 500));
    }
}

// Auth endpoints implementation
void ApiController::handle_login(http_request request) {
    auto handler = [this](http_request& req, boost::uuids::uuid) {
        auto json = req.extract_json().get();
        
        std::string username = utility::conversions::to_utf8string(json[U("username")].as_string());
        std::string password = utility::conversions::to_utf8string(json[U("password")].as_string());
        std::string mfa_code = utility::conversions::to_utf8string(json.has_field(U("mfa_code")) ? 
            json[U("mfa_code")].as_string() : U(""));

        auto result = m_auth_service->login(username, password, mfa_code);
        
        if (!result.first) {
            req.reply(status_codes::Unauthorized, 
                create_error_response("Invalid credentials", 401));
            return;
        }

        web::json::value response;
        response[U("token")] = web::json::value::string(utility::conversions::to_string_t(result.second));
        req.reply(status_codes::OK, create_success_response(response));
    };

    handle_request(request, handler, false);
}

void ApiController::handle_logout(http_request request) {
    auto handler = [this](http_request& req, boost::uuids::uuid user_id) {
        auto headers = req.headers();
        auto auth_header = headers.find(U("Authorization"));
        std::string token = utility::conversions::to_utf8string(auth_header->second).substr(7);
        
        m_auth_service->logout(token);
        req.reply(status_codes::OK, create_success_response(web::json::value::object()));
    };

    handle_request(request, handler, true);
}

void ApiController::handle_register(http_request request) {
    auto handler = [this](http_request& req, boost::uuids::uuid) {
        auto json = req.extract_json().get();
        
        std::string username = utility::conversions::to_utf8string(json[U("username")].as_string());
        std::string password = utility::conversions::to_utf8string(json[U("password")].as_string());

        if (m_auth_service->register_user(username, password)) {
            req.reply(status_codes::Created, create_success_response(web::json::value::object()));
        } else {
            req.reply(status_codes::BadRequest, 
                create_error_response("Username already exists", 400));
        }
    };

    handle_request(request, handler, false);
}

void ApiController::handle_mfa_setup(http_request request) {
    auto handler = [this](http_request& req, boost::uuids::uuid user_id) {
        auto setup_result = m_auth_service->setup_mfa(user_id);
        
        web::json::value response;
        response[U("secret")] = web::json::value::string(utility::conversions::to_string_t(setup_result.first));
        response[U("qr_code")] = web::json::value::string(utility::conversions::to_string_t(setup_result.second));
        
        req.reply(status_codes::OK, create_success_response(response));
    };

    handle_request(request, handler, true);
}

void ApiController::handle_mfa_verify(http_request request) {
    auto handler = [this](http_request& req, boost::uuids::uuid user_id) {
        auto json = req.extract_json().get();
        std::string code = utility::conversions::to_utf8string(json[U("code")].as_string());
        
        if (m_auth_service->verify_mfa(user_id, code)) {
            req.reply(status_codes::OK, create_success_response(web::json::value::object()));
        } else {
            req.reply(status_codes::BadRequest, 
                create_error_response("Invalid MFA code", 400));
        }
    };

    handle_request(request, handler, true);
}

// User endpoints implementation
void ApiController::handle_get_user(http_request request) {
    auto handler = [this](http_request& req, boost::uuids::uuid user_id) {
        auto user = m_db_service->getUser(user_id);
        
        if (!user) {
            req.reply(status_codes::NotFound, 
                create_error_response("User not found", 404));
            return;
        }

        web::json::value response;
        response[U("id")] = web::json::value::string(utility::conversions::to_string_t(boost::uuids::to_string(user->id)));
        response[U("username")] = web::json::value::string(utility::conversions::to_string_t(user->username));
        response[U("has_mfa")] = web::json::value::boolean(user->has_mfa_enabled());
        
        req.reply(status_codes::OK, create_success_response(response));
    };

    handle_request(request, handler, true);
}

void ApiController::handle_update_user(http_request request) {
    auto handler = [this](http_request& req, boost::uuids::uuid user_id) {
        auto json = req.extract_json().get();
        
        if (json.has_field(U("password"))) {
            std::string new_password = utility::conversions::to_utf8string(json[U("password")].as_string());
            m_auth_service->update_password(user_id, new_password);
        }

        req.reply(status_codes::OK, create_success_response(web::json::value::object()));
    };

    handle_request(request, handler, true);
}

// Group endpoints implementation
void ApiController::handle_create_group(http_request request) {
    auto handler = [this](http_request& req, boost::uuids::uuid user_id) {
        auto json = req.extract_json().get();
        std::string name = utility::conversions::to_utf8string(json[U("name")].as_string());

        models::Group group;
        group.id = boost::uuids::random_generator()();
        group.name = name;
        group.owner_id = user_id;
        group.created_at = std::chrono::system_clock::now();

        if (m_db_service->createGroup(group)) {
            web::json::value response;
            response[U("id")] = web::json::value::string(utility::conversions::to_string_t(boost::uuids::to_string(group.id)));
            req.reply(status_codes::Created, create_success_response(response));
        } else {
            req.reply(status_codes::BadRequest, 
                create_error_response("Failed to create group", 400));
        }
    };

    handle_request(request, handler, true);
}

void ApiController::handle_get_groups(http_request request) {
    auto handler = [this](http_request& req, boost::uuids::uuid user_id) {
        auto groups = m_db_service->getUserGroups(user_id);
        
        web::json::value array = web::json::value::array();
        int index = 0;
        
        for (const auto& group : groups) {
            web::json::value group_json;
            group_json[U("id")] = web::json::value::string(utility::conversions::to_string_t(boost::uuids::to_string(group.id)));
            group_json[U("name")] = web::json::value::string(utility::conversions::to_string_t(group.name));
            group_json[U("is_owner")] = web::json::value::boolean(group.owner_id == user_id);
            array[index++] = group_json;
        }

        req.reply(status_codes::OK, create_success_response(array));
    };

    handle_request(request, handler, true);
}

void ApiController::handle_update_group(http_request request) {
    auto handler = [this](http_request& req, boost::uuids::uuid user_id) {
        auto json = req.extract_json().get();
        std::string group_id_str = utility::conversions::to_utf8string(req.relative_uri().path()).substr(8);
        boost::uuids::uuid group_id = boost::uuids::string_generator()(group_id_str);

        auto group = m_db_service->getGroup(group_id);
        if (!group || group->owner_id != user_id) {
            req.reply(status_codes::NotFound, 
                create_error_response("Group not found or access denied", 404));
            return;
        }

        group->name = utility::conversions::to_utf8string(json[U("name")].as_string());
        
        if (m_db_service->updateGroup(*group)) {
            req.reply(status_codes::OK, create_success_response(web::json::value::object()));
        } else {
            req.reply(status_codes::BadRequest, 
                create_error_response("Failed to update group", 400));
        }
    };

    handle_request(request, handler, true);
}

void ApiController::handle_delete_group(http_request request) {
    auto handler = [this](http_request& req, boost::uuids::uuid user_id) {
        std::string group_id_str = utility::conversions::to_utf8string(req.relative_uri().path()).substr(8);
        boost::uuids::uuid group_id = boost::uuids::string_generator()(group_id_str);

        auto group = m_db_service->getGroup(group_id);
        if (!group || group->owner_id != user_id) {
            req.reply(status_codes::NotFound, 
                create_error_response("Group not found or access denied", 404));
            return;
        }

        if (m_db_service->deleteGroup(group_id)) {
            req.reply(status_codes::OK, create_success_response(web::json::value::object()));
        } else {
            req.reply(status_codes::BadRequest, 
                create_error_response("Failed to delete group", 400));
        }
    };

    handle_request(request, handler, true);
}

void ApiController::handle_add_group_member(http_request request) {
    auto handler = [this](http_request& req, boost::uuids::uuid user_id) {
        std::string group_id_str = utility::conversions::to_utf8string(req.relative_uri().path());
        group_id_str = group_id_str.substr(8, group_id_str.find("/members") - 8);
        boost::uuids::uuid group_id = boost::uuids::string_generator()(group_id_str);

        auto json = req.extract_json().get();
        std::string member_username = utility::conversions::to_utf8string(json[U("username")].as_string());
        int access_level = json[U("access_level")].as_integer();

        // Verify group ownership or admin rights
        if (!m_db_service->isGroupAdmin(user_id, group_id)) {
            req.reply(status_codes::Forbidden, 
                create_error_response("Insufficient permissions", 403));
            return;
        }

        // Get user by username
        auto new_member = m_db_service->getUserByUsername(member_username);
        if (!new_member) {
            req.reply(status_codes::NotFound, 
                create_error_response("User not found", 404));
            return;
        }

        models::GroupMember member;
        member.group_id = group_id;
        member.user_id = new_member->id;
        member.access_level = access_level;

        if (m_db_service->addGroupMember(member)) {
            req.reply(status_codes::OK, create_success_response(web::json::value::object()));
        } else {
            req.reply(status_codes::BadRequest, 
                create_error_response("Failed to add group member", 400));
        }
    };

    handle_request(request, handler, true);
}

void ApiController::handle_remove_group_member(http_request request) {
    auto handler = [this](http_request& req, boost::uuids::uuid user_id) {
        auto uri_parts = uri::split_path(uri::decode(req.relative_uri().path()));
        boost::uuids::uuid group_id = boost::uuids::string_generator()(uri_parts[1]);
        boost::uuids::uuid member_id = boost::uuids::string_generator()(uri_parts[3]);

        // Verify group ownership or admin rights
        if (!m_db_service->isGroupAdmin(user_id, group_id)) {
            req.reply(status_codes::Forbidden, 
                create_error_response("Insufficient permissions", 403));
            return;
        }

        if (m_db_service->removeGroupMember(group_id, member_id)) {
            req.reply(status_codes::OK, create_success_response(web::json::value::object()));
        } else {
            req.reply(status_codes::BadRequest, 
                create_error_response("Failed to remove group member", 400));
        }
    };

    handle_request(request, handler, true);
}

void ApiController::handle_create_password(http_request request) {
    auto handler = [this](http_request& req, boost::uuids::uuid user_id) {
        auto json = req.extract_json().get();
        
        // Extract password details
        boost::uuids::uuid group_id = boost::uuids::string_generator()(
            utility::conversions::to_utf8string(json[U("group_id")].as_string()));
        std::string title = utility::conversions::to_utf8string(json[U("title")].as_string());
        std::string password_value = utility::conversions::to_utf8string(json[U("password")].as_string());

        // Verify group access
        if (!m_db_service->isGroupMember(user_id, group_id)) {
            req.reply(status_codes::Forbidden, 
                create_error_response("Access denied", 403));
            return;
        }

        // Generate group encryption key (in real implementation, this would be derived from user's master key)
        auto key = m_encryption_service->generateKey();
        
        // Encrypt the password
        auto encrypted = m_encryption_service->encrypt(password_value, key);

        // Create password entry
        models::Password pwd;
        pwd.id = boost::uuids::random_generator()();
        pwd.group_id = group_id;
        pwd.title = title;
        pwd.encrypted_password = encrypted.ciphertext;
        pwd.iv = encrypted.iv;
        pwd.tag = encrypted.tag;
        pwd.created_at = std::chrono::system_clock::now();
        pwd.updated_at = pwd.created_at;

        if (m_db_service->createPassword(pwd)) {
            web::json::value response;
            response[U("id")] = web::json::value::string(
                utility::conversions::to_string_t(boost::uuids::to_string(pwd.id)));
            req.reply(status_codes::Created, create_success_response(response));
        } else {
            req.reply(status_codes::BadRequest, 
                create_error_response("Failed to create password", 400));
        }
    };

    handle_request(request, handler, true);
}

void ApiController::handle_get_passwords(http_request request) {
    auto handler = [this](http_request& req, boost::uuids::uuid user_id) {
        std::string group_id_str = utility::conversions::to_utf8string(req.relative_uri().path());
        group_id_str = group_id_str.substr(8, group_id_str.find("/passwords") - 8);
        boost::uuids::uuid group_id = boost::uuids::string_generator()(group_id_str);

        // Verify group access
        if (!m_db_service->isGroupMember(user_id, group_id)) {
            req.reply(status_codes::Forbidden, 
                create_error_response("Access denied", 403));
            return;
        }

        auto passwords = m_db_service->getGroupPasswords(group_id);
        
        web::json::value array = web::json::value::array();
        int index = 0;
        
        for (const auto& pwd : passwords) {
            web::json::value pwd_json;
            pwd_json[U("id")] = web::json::value::string(
                utility::conversions::to_string_t(boost::uuids::to_string(pwd.id)));
            pwd_json[U("title")] = web::json::value::string(
                utility::conversions::to_string_t(pwd.title));
            pwd_json[U("created_at")] = web::json::value::string(
                utility::conversions::to_string_t(std::to_string(
                    std::chrono::system_clock::to_time_t(pwd.created_at))));
            pwd_json[U("updated_at")] = web::json::value::string(
                utility::conversions::to_string_t(std::to_string(
                    std::chrono::system_clock::to_time_t(pwd.updated_at))));
            array[index++] = pwd_json;
        }

        req.reply(status_codes::OK, create_success_response(array));
    };

    handle_request(request, handler, true);
}

void ApiController::handle_update_password(http_request request) {
    auto handler = [this](http_request& req, boost::uuids::uuid user_id) {
        std::string password_id_str = utility::conversions::to_utf8string(req.relative_uri().path()).substr(11);
        boost::uuids::uuid password_id = boost::uuids::string_generator()(password_id_str);

        // Verify password access with write permissions
        if (!m_db_service->hasAccessToPassword(user_id, password_id, 1)) {
            req.reply(status_codes::Forbidden, 
                create_error_response("Access denied", 403));
            return;
        }

        auto json = req.extract_json().get();
        auto password = m_db_service->getPassword(password_id);
        
        if (!password) {
            req.reply(status_codes::NotFound, 
                create_error_response("Password not found", 404));
            return;
        }

        // Update password fields
        if (json.has_field(U("title"))) {
            password->title = utility::conversions::to_utf8string(json[U("title")].as_string());
        }

        if (json.has_field(U("password"))) {
            std::string new_password = utility::conversions::to_utf8string(json[U("password")].as_string());
            auto key = m_encryption_service->generateKey(); // In real implementation, derive from master key
            auto encrypted = m_encryption_service->encrypt(new_password, key);
            
            password->encrypted_password = encrypted.ciphertext;
            password->iv = encrypted.iv;
            password->tag = encrypted.tag;
        }

        password->updated_at = std::chrono::system_clock::now();

        if (m_db_service->updatePassword(*password)) {
            req.reply(status_codes::OK, create_success_response(web::json::value::object()));
        } else {
            req.reply(status_codes::BadRequest, 
                create_error_response("Failed to update password", 400));
        }
    };

    handle_request(request, handler, true);
}

void ApiController::handle_delete_password(http_request request) {
    auto handler = [this](http_request& req, boost::uuids::uuid user_id) {
        std::string password_id_str = utility::conversions::to_utf8string(req.relative_uri().path()).substr(11);
        boost::uuids::uuid password_id = boost::uuids::string_generator()(password_id_str);

        // Verify password access with write permissions
        if (!m_db_service->hasAccessToPassword(user_id, password_id, 1)) {
            req.reply(status_codes::Forbidden, 
                create_error_response("Access denied", 403));
            return;
        }

        if (m_db_service->deletePassword(password_id)) {
            req.reply(status_codes::OK, create_success_response(web::json::value::object()));
        } else {
            req.reply(status_codes::BadRequest, 
                create_error_response("Failed to delete password", 400));
        }
    };

    handle_request(request, handler, true);
}

} // namespace api
} // namespace btpv