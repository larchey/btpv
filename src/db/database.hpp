// src/db/database.hpp
#pragma once

#include <memory>
#include <optional>
#include <vector>
#include <pqxx/pqxx>
#include "../models/user.hpp"
#include "../models/group.hpp"
#include "../models/password.hpp"
#include "../models/group_member.hpp"

namespace btpv {
namespace db {

class DatabaseService {
public:
    explicit DatabaseService(const std::string& connection_string);
    ~DatabaseService() = default;

    // Prevent copying and assignment
    DatabaseService(const DatabaseService&) = delete;
    DatabaseService& operator=(const DatabaseService&) = delete;
    
    // User operations
    bool createUser(const models::User& user);
    std::optional<models::User> getUser(const boost::uuids::uuid& id);
    std::optional<models::User> getUserByUsername(const std::string& username);
    bool updateUser(const models::User& user);
    bool deleteUser(const boost::uuids::uuid& id);
    
    // Group operations
    bool createGroup(const models::Group& group);
    std::optional<models::Group> getGroup(const boost::uuids::uuid& id);
    std::vector<models::Group> getUserGroups(const boost::uuids::uuid& user_id);
    bool updateGroup(const models::Group& group);
    bool deleteGroup(const boost::uuids::uuid& id);
    
    // Password operations
    bool createPassword(const models::Password& password);
    std::optional<models::Password> getPassword(const boost::uuids::uuid& id);
    std::vector<models::Password> getGroupPasswords(const boost::uuids::uuid& group_id);
    bool updatePassword(const models::Password& password);
    bool deletePassword(const boost::uuids::uuid& id);
    
    // Group member operations
    bool addGroupMember(const models::GroupMember& member);
    bool updateGroupMemberAccess(const models::GroupMember& member);
    bool removeGroupMember(const boost::uuids::uuid& group_id, const boost::uuids::uuid& user_id);
    std::vector<models::GroupMember> getGroupMembers(const boost::uuids::uuid& group_id);
    
    // Permission checks
    bool hasAccessToPassword(const boost::uuids::uuid& user_id, 
                           const boost::uuids::uuid& password_id,
                           int required_level);
    bool isGroupAdmin(const boost::uuids::uuid& user_id, 
                     const boost::uuids::uuid& group_id);
    bool isGroupMember(const boost::uuids::uuid& user_id, 
                      const boost::uuids::uuid& group_id);

    // Password history operations
    bool addPasswordHistory(const boost::uuids::uuid& password_id,
                          const std::vector<unsigned char>& encrypted_password,
                          const std::vector<unsigned char>& iv,
                          const std::vector<unsigned char>& tag);
    std::vector<models::Password> getPasswordHistory(const boost::uuids::uuid& password_id);

    // Transaction management
    class Transaction {
    public:
        explicit Transaction(DatabaseService& db);
        ~Transaction();
        
        void commit();
        void rollback();
        
    private:
        std::unique_ptr<pqxx::work> m_txn;
        bool m_committed;
    };
    
    // Create a transaction
    Transaction beginTransaction();

private:
    std::unique_ptr<pqxx::connection> m_conn;
    
    // Helper methods
    template<typename T>
    std::string uuidToString(const T& uuid);
    
    // Internal methods that work with an existing transaction
    bool createUser(pqxx::work& txn, const models::User& user);
    bool createGroup(pqxx::work& txn, const models::Group& group);
    bool createPassword(pqxx::work& txn, const models::Password& password);
    
    // Error handling
    void handleDatabaseError(const std::string& operation, const std::exception& e);
    
    // Connection management
    void ensureConnection();
    void reconnectIfNeeded();
    
    // Query helpers
    template<typename... Args>
    pqxx::result executeQuery(const std::string& sql, Args&&... args);
    
    template<typename... Args>
    pqxx::result executeQueryWithTransaction(const std::string& sql, Args&&... args);
};

} // namespace db
} // namespace btpv