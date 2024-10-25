// src/db/database.cpp
#include "database.hpp"
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <sstream>
#include <stdexcept>

namespace btpv {
namespace db {

DatabaseService::DatabaseService(const std::string& connection_string) {
    try {
        m_conn = std::make_unique<pqxx::connection>(connection_string);
        if (!m_conn->is_open()) {
            throw std::runtime_error("Failed to open database connection");
        }
    } catch (const std::exception& e) {
        throw std::runtime_error("Database connection error: " + std::string(e.what()));
    }
}

// Helper method to convert UUID to string
template<typename T>
std::string DatabaseService::uuidToString(const T& uuid) {
    return boost::uuids::to_string(uuid);
}

// User operations
bool DatabaseService::createUser(const models::User& user) {
    try {
        pqxx::work txn(*m_conn);
        
        std::string sql = R"(
            INSERT INTO users (id, username, password_hash, salt, mfa_secret, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
        )";
        
        txn.exec_params(sql,
            uuidToString(user.id),
            user.username,
            user.password_hash,
            pqxx::binary_cast(user.salt),
            user.mfa_secret,
            std::chrono::system_clock::to_time_t(user.created_at)
        );
        
        txn.commit();
        return true;
    } catch (const std::exception& e) {
        // Log error
        return false;
    }
}

std::optional<models::User> DatabaseService::getUserByUsername(const std::string& username) {
    try {
        pqxx::work txn(*m_conn);
        
        std::string sql = R"(
            SELECT id, username, password_hash, salt, mfa_secret, created_at
            FROM users WHERE username = $1
        )";
        
        auto result = txn.exec_params1(sql, username);
        
        models::User user;
        user.id = boost::uuids::string_generator()(result[0].as<std::string>());
        user.username = result[1].as<std::string>();
        user.password_hash = result[2].as<std::string>();
        user.salt = pqxx::binary_cast<std::vector<unsigned char>>(result[3]);
        user.mfa_secret = result[4].as<std::string>();
        user.created_at = std::chrono::system_clock::from_time_t(result[5].as<time_t>());
        
        return user;
    } catch (const std::exception& e) {
        return std::nullopt;
    }
}

// Group operations
bool DatabaseService::createGroup(const models::Group& group) {
    try {
        pqxx::work txn(*m_conn);
        
        std::string sql = R"(
            INSERT INTO groups (id, name, owner_id, created_at)
            VALUES ($1, $2, $3, $4)
        )";
        
        txn.exec_params(sql,
            uuidToString(group.id),
            group.name,
            uuidToString(group.owner_id),
            std::chrono::system_clock::to_time_t(group.created_at)
        );
        
        txn.commit();
        return true;
    } catch (const std::exception& e) {
        return false;
    }
}

std::vector<models::Group> DatabaseService::getUserGroups(const boost::uuids::uuid& user_id) {
    try {
        pqxx::work txn(*m_conn);
        
        std::string sql = R"(
            SELECT g.id, g.name, g.owner_id, g.created_at
            FROM groups g
            INNER JOIN group_members gm ON g.id = gm.group_id
            WHERE gm.user_id = $1
            OR g.owner_id = $1
        )";
        
        auto result = txn.exec_params(sql, uuidToString(user_id));
        
        std::vector<models::Group> groups;
        for (const auto& row : result) {
            models::Group group;
            group.id = boost::uuids::string_generator()(row[0].as<std::string>());
            group.name = row[1].as<std::string>();
            group.owner_id = boost::uuids::string_generator()(row[2].as<std::string>());
            group.created_at = std::chrono::system_clock::from_time_t(row[3].as<time_t>());
            groups.push_back(group);
        }
        
        return groups;
    } catch (const std::exception& e) {
        return std::vector<models::Group>();
    }
}

// Password operations
bool DatabaseService::createPassword(const models::Password& password) {
    try {
        pqxx::work txn(*m_conn);
        
        std::string sql = R"(
            INSERT INTO passwords 
            (id, group_id, title, encrypted_password, iv, tag, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        )";
        
        txn.exec_params(sql,
            uuidToString(password.id),
            uuidToString(password.group_id),
            password.title,
            pqxx::binary_cast(password.encrypted_password),
            pqxx::binary_cast(password.iv),
            pqxx::binary_cast(password.tag),
            std::chrono::system_clock::to_time_t(password.created_at),
            std::chrono::system_clock::to_time_t(password.updated_at)
        );
        
        txn.commit();
        return true;
    } catch (const std::exception& e) {
        return false;
    }
}

std::vector<models::Password> DatabaseService::getGroupPasswords(const boost::uuids::uuid& group_id) {
    try {
        pqxx::work txn(*m_conn);
        
        std::string sql = R"(
            SELECT id, group_id, title, encrypted_password, iv, tag, created_at, updated_at
            FROM passwords
            WHERE group_id = $1
        )";
        
        auto result = txn.exec_params(sql, uuidToString(group_id));
        
        std::vector<models::Password> passwords;
        for (const auto& row : result) {
            models::Password pwd;
            pwd.id = boost::uuids::string_generator()(row[0].as<std::string>());
            pwd.group_id = boost::uuids::string_generator()(row[1].as<std::string>());
            pwd.title = row[2].as<std::string>();
            pwd.encrypted_password = pqxx::binary_cast<std::vector<unsigned char>>(row[3]);
            pwd.iv = pqxx::binary_cast<std::vector<unsigned char>>(row[4]);
            pwd.tag = pqxx::binary_cast<std::vector<unsigned char>>(row[5]);
            pwd.created_at = std::chrono::system_clock::from_time_t(row[6].as<time_t>());
            pwd.updated_at = std::chrono::system_clock::from_time_t(row[7].as<time_t>());
            passwords.push_back(pwd);
        }
        
        return passwords;
    } catch (const std::exception& e) {
        return std::vector<models::Password>();
    }
}

// Group member operations
bool DatabaseService::addGroupMember(const models::GroupMember& member) {
    try {
        pqxx::work txn(*m_conn);
        
        // First check if user has permission to add members
        std::string check_sql = R"(
            SELECT 1 FROM groups 
            WHERE id = $1 AND owner_id = $2
            UNION
            SELECT 1 FROM group_members 
            WHERE group_id = $1 AND user_id = $2 AND access_level = 2
        )";
        
        auto result = txn.exec_params(check_sql,
            uuidToString(member.group_id),
            uuidToString(member.user_id)
        );
        
        if (result.empty()) {
            return false; // No permission
        }
        
        std::string sql = R"(
            INSERT INTO group_members (group_id, user_id, access_level)
            VALUES ($1, $2, $3)
            ON CONFLICT (group_id, user_id) 
            DO UPDATE SET access_level = EXCLUDED.access_level
        )";
        
        txn.exec_params(sql,
            uuidToString(member.group_id),
            uuidToString(member.user_id),
            member.access_level
        );
        
        txn.commit();
        return true;
    } catch (const std::exception& e) {
        return false;
    }
}

std::vector<models::GroupMember> DatabaseService::getGroupMembers(const boost::uuids::uuid& group_id) {
    try {
        pqxx::work txn(*m_conn);
        
        std::string sql = R"(
            SELECT group_id, user_id, access_level
            FROM group_members
            WHERE group_id = $1
        )";
        
        auto result = txn.exec_params(sql, uuidToString(group_id));
        
        std::vector<models::GroupMember> members;
        for (const auto& row : result) {
            models::GroupMember member;
            member.group_id = boost::uuids::string_generator()(row[0].as<std::string>());
            member.user_id = boost::uuids::string_generator()(row[1].as<std::string>());
            member.access_level = row[2].as<int>();
            members.push_back(member);
        }
        
        return members;
    } catch (const std::exception& e) {
        return std::vector<models::GroupMember>();
    }
}

bool DatabaseService::hasAccessToPassword(
    const boost::uuids::uuid& user_id,
    const boost::uuids::uuid& password_id,
    int required_level) {
    
    try {
        pqxx::work txn(*m_conn);
        
        std::string sql = R"(
            SELECT 1 FROM passwords p
            INNER JOIN groups g ON p.group_id = g.id
            LEFT JOIN group_members gm ON g.id = gm.group_id
            WHERE p.id = $1 AND
            (g.owner_id = $2 OR 
             (gm.user_id = $2 AND gm.access_level >= $3))
        )";
        
        auto result = txn.exec_params(sql,
            uuidToString(password_id),
            uuidToString(user_id),
            required_level
        );
        
        return !result.empty();
    } catch (const std::exception& e) {
        return false;
    }
}

} // namespace db
} // namespace btpv