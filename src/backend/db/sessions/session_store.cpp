// src/db/sessions/session_store.cpp
#include "session_store.hpp"
#include <sstream>
#include "../../utils/error.hpp"
#include "../../utils/logging.hpp"

namespace btpv {
namespace db {

SessionStore::SessionStore(std::shared_ptr<DatabaseService> db_service)
    : m_db_service(db_service) {}

bool SessionStore::createSession(const models::Session& session) {
    try {
        pqxx::work txn(*m_db_service->getConnection());
        
        std::string sql = R"(
            INSERT INTO sessions 
            (id, user_id, token_hash, created_at, expires_at, last_activity, ip_address, user_agent)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        )";
        
        txn.exec_params(sql,
            boost::uuids::to_string(session.id),
            boost::uuids::to_string(session.user_id),
            session.token_hash,
            std::chrono::system_clock::to_time_t(session.created_at),
            std::chrono::system_clock::to_time_t(session.expires_at),
            std::chrono::system_clock::to_time_t(session.last_activity),
            session.ip_address,
            session.user_agent
        );
        
        txn.commit();
        return true;
    }
    catch (const std::exception& e) {
        utils::LoggingService::instance().log_error(
            "SessionStore",
            "Failed to create session: " + std::string(e.what())
        );
        return false;
    }
}

bool SessionStore::updateSession(const models::Session& session) {
    try {
        pqxx::work txn(*m_db_service->getConnection());
        
        std::string sql = R"(
            UPDATE sessions 
            SET last_activity = $1,
                expires_at = $2,
                ip_address = $3,
                user_agent = $4
            WHERE id = $5
        )";
        
        txn.exec_params(sql,
            std::chrono::system_clock::to_time_t(session.last_activity),
            std::chrono::system_clock::to_time_t(session.expires_at),
            session.ip_address,
            session.user_agent,
            boost::uuids::to_string(session.id)
        );
        
        txn.commit();
        return true;
    }
    catch (const std::exception& e) {
        utils::LoggingService::instance().log_error(
            "SessionStore",
            "Failed to update session: " + std::string(e.what())
        );
        return false;
    }
}

bool SessionStore::deleteSession(const std::string& token_hash) {
    try {
        pqxx::work txn(*m_db_service->getConnection());
        
        std::string sql = "DELETE FROM sessions WHERE token_hash = $1";
        txn.exec_params(sql, token_hash);
        
        txn.commit();
        return true;
    }
    catch (const std::exception& e) {
        utils::LoggingService::instance().log_error(
            "SessionStore",
            "Failed to delete session: " + std::string(e.what())
        );
        return false;
    }
}

bool SessionStore::deleteUserSessions(const boost::uuids::uuid& user_id) {
    try {
        pqxx::work txn(*m_db_service->getConnection());
        
        std::string sql = "DELETE FROM sessions WHERE user_id = $1";
        txn.exec_params(sql, boost::uuids::to_string(user_id));
        
        txn.commit();
        return true;
    }
    catch (const std::exception& e) {
        utils::LoggingService::instance().log_error(
            "SessionStore",
            "Failed to delete user sessions: " + std::string(e.what())
        );
        return false;
    }
}

std::optional<models::Session> SessionStore::getSession(const boost::uuids::uuid& session_id) {
    try {
        pqxx::work txn(*m_db_service->getConnection());
        
        std::string sql = R"(
            SELECT id, user_id, token_hash, created_at, expires_at, last_activity, 
                   ip_address, user_agent
            FROM sessions 
            WHERE id = $1
        )";
        
        auto result = txn.exec_params1(sql, boost::uuids::to_string(session_id));
        
        models::Session session;
        session.id = boost::uuids::string_generator()(result[0].as<std::string>());
        session.user_id = boost::uuids::string_generator()(result[1].as<std::string>());
        session.token_hash = result[2].as<std::string>();
        session.created_at = std::chrono::system_clock::from_time_t(result[3].as<time_t>());
        session.expires_at = std::chrono::system_clock::from_time_t(result[4].as<time_t>());
        session.last_activity = std::chrono::system_clock::from_time_t(result[5].as<time_t>());
        session.ip_address = result[6].as<std::string>();
        session.user_agent = result[7].as<std::string>();
        
        return session;
    }
    catch (const std::exception& e) {
        utils::LoggingService::instance().log_error(
            "SessionStore",
            "Failed to get session: " + std::string(e.what())
        );
        return std::nullopt;
    }
}

std::optional<models::Session> SessionStore::getSessionByToken(const std::string& token_hash) {
    try {
        pqxx::work txn(*m_db_service->getConnection());
        
        std::string sql = R"(
            SELECT id, user_id, token_hash, created_at, expires_at, last_activity, 
                   ip_address, user_agent
            FROM sessions 
            WHERE token_hash = $1
        )";
        
        auto result = txn.exec_params1(sql, token_hash);
        
        models::Session session;
        session.id = boost::uuids::string_generator()(result[0].as<std::string>());
        session.user_id = boost::uuids::string_generator()(result[1].as<std::string>());
        session.token_hash = result[2].as<std::string>();
        session.created_at = std::chrono::system_clock::from_time_t(result[3].as<time_t>());
        session.expires_at = std::chrono::system_clock::from_time_t(result[4].as<time_t>());
        session.last_activity = std::chrono::system_clock::from_time_t(result[5].as<time_t>());
        session.ip_address = result[6].as<std::string>();
        session.user_agent = result[7].as<std::string>();
        
        return session;
    }
    catch (const std::exception& e) {
        utils::LoggingService::instance().log_error(
            "SessionStore",
            "Failed to get session by token: " + std::string(e.what())
        );
        return std::nullopt;
    }
}

std::vector<models::Session> SessionStore::getUserSessions(const boost::uuids::uuid& user_id) {
    try {
        pqxx::work txn(*m_db_service->getConnection());
        
        std::string sql = R"(
            SELECT id, user_id, token_hash, created_at, expires_at, last_activity, 
                   ip_address, user_agent
            FROM sessions 
            WHERE user_id = $1
            ORDER BY created_at DESC
        )";
        
        auto result = txn.exec_params(sql, boost::uuids::to_string(user_id));
        
        std::vector<models::Session> sessions;
        for (const auto& row : result) {
            models::Session session;
            session.id = boost::uuids::string_generator()(row[0].as<std::string>());
            session.user_id = boost::uuids::string_generator()(row[1].as<std::string>());
            session.token_hash = row[2].as<std::string>();
            session.created_at = std::chrono::system_clock::from_time_t(row[3].as<time_t>());
            session.expires_at = std::chrono::system_clock::from_time_t(row[4].as<time_t>());
            session.last_activity = std::chrono::system_clock::from_time_t(row[5].as<time_t>());
            session.ip_address = row[6].as<std::string>();
            session.user_agent = row[7].as<std::string>();
            sessions.push_back(session);
        }
        
        return sessions;
    }
    catch (const std::exception& e) {
        utils::LoggingService::instance().log_error(
            "SessionStore",
            "Failed to get user sessions: " + std::string(e.what())
        );
        return std::vector<models::Session>();
    }
}

void SessionStore::deleteExpiredSessions(const std::chrono::system_clock::time_point& current_time) {
    try {
        pqxx::work txn(*m_db_service->getConnection());
        
        std::string sql = "DELETE FROM sessions WHERE expires_at <= $1";
        txn.exec_params(sql, std::chrono::system_clock::to_time_t(current_time));
        
        txn.commit();
    }
    catch (const std::exception& e) {
        utils::LoggingService::instance().log_error(
            "SessionStore",
            "Failed to delete expired sessions: " + std::string(e.what())
        );
    }
}

void SessionStore::updateSessionActivity(const boost::uuids::uuid& session_id) {
    try {
        pqxx::work txn(*m_db_service->getConnection());
        
        auto now = std::chrono::system_clock::now();
        auto new_expiry = getSessionExpiry(now);
        
        std::string sql = R"(
            UPDATE sessions 
            SET last_activity = $1,
                expires_at = $2
            WHERE id = $3
        )";
        
        txn.exec_params(sql,
            std::chrono::system_clock::to_time_t(now),
            std::chrono::system_clock::to_time_t(new_expiry),
            boost::uuids::to_string(session_id)
        );
        
        txn.commit();
    }
    catch (const std::exception& e) {
        utils::LoggingService::instance().log_error(
            "SessionStore",
            "Failed to update session activity: " + std::string(e.what())
        );
    }
}

bool SessionStore::checkRateLimit(const std::string& key, int limit, int window_seconds) {
    try {
        pqxx::work txn(*m_db_service->getConnection());
        
        // Get current count within window
        std::string sql = R"(
            SELECT COUNT(*) FROM rate_limits 
            WHERE key = $1 AND timestamp > NOW() - INTERVAL '$2 seconds'
        )";
        
        auto result = txn.exec_params1(sql, key, window_seconds);
        int count = result[0].as<int>();
        
        return count < limit;
    }
    catch (const std::exception& e) {
        utils::LoggingService::instance().log_error(
            "SessionStore",
            "Failed to check rate limit: " + std::string(e.what())
        );
        return false;
    }
}

void SessionStore::incrementRateLimit(const std::string& key) {
    try {
        pqxx::work txn(*m_db_service->getConnection());
        
        std::string sql = R"(
            INSERT INTO rate_limits (key, timestamp)
            VALUES ($1, NOW())
        )";
        
        txn.exec_params(sql, key);
        txn.commit();
    }
    catch (const std::exception& e) {
        utils::LoggingService::instance().log_error(
            "SessionStore",
            "Failed to increment rate limit: " + std::string(e.what())
        );
    }
}

bool SessionStore::isSessionValid(const models::Session& session) {
    auto now = std::chrono::system_clock::now();
    return session.expires_at > now;
}

std::chrono::system_clock::time_point SessionStore::getSessionExpiry(
    const std::chrono::system_clock::time_point& creation_time) {
    // Get session timeout from configuration (default 1 hour)
    int timeout_seconds = utils::ConfigurationService::instance().get_session_timeout();
    return creation_time + std::chrono::seconds(timeout_seconds);
}

} // namespace db
} // namespace btpv