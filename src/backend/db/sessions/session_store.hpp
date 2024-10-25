// src/db/sessions/session_store.hpp
#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <chrono>
#include <boost/uuid/uuid.hpp>
#include "session.hpp"
#include "../database.hpp"

namespace btpv {
namespace db {

class SessionStore {
public:
    explicit SessionStore(std::shared_ptr<DatabaseService> db_service);
    ~SessionStore() = default;

    // Session management
    bool createSession(const models::Session& session);
    bool updateSession(const models::Session& session);
    bool deleteSession(const std::string& token_hash);
    bool deleteUserSessions(const boost::uuids::uuid& user_id);
    
    // Session retrieval
    std::optional<models::Session> getSession(const boost::uuids::uuid& session_id);
    std::optional<models::Session> getSessionByToken(const std::string& token_hash);
    std::vector<models::Session> getUserSessions(const boost::uuids::uuid& user_id);
    
    // Session cleanup
    void deleteExpiredSessions(const std::chrono::system_clock::time_point& current_time);
    void updateSessionActivity(const boost::uuids::uuid& session_id);

    // Rate limiting
    bool checkRateLimit(const std::string& key, int limit, int window_seconds);
    void incrementRateLimit(const std::string& key);

private:
    std::shared_ptr<DatabaseService> m_db_service;

    // Helper methods
    bool isSessionValid(const models::Session& session);
    std::chrono::system_clock::time_point getSessionExpiry(
        const std::chrono::system_clock::time_point& creation_time);
};

} // namespace db
} // namespace btpv