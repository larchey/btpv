// src/db/migrations.hpp
#pragma once

#include <string>
#include <vector>
#include <pqxx/pqxx>

namespace btpv {
namespace db {

class DatabaseMigration {
public:
    static bool run_migrations(pqxx::connection& conn);

private:
    static bool create_migrations_table(pqxx::connection& conn);
    static int get_current_version(pqxx::connection& conn);

    // Define all database migrations
    static inline const std::vector<std::string> MIGRATIONS = {
        // Migration 1: Initial schema
        R"(
            CREATE TABLE users (
                id UUID PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                salt BYTEA NOT NULL,
                mfa_secret VARCHAR(255),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP WITH TIME ZONE,
                failed_login_attempts INTEGER DEFAULT 0,
                account_locked_until TIMESTAMP WITH TIME ZONE
            );

            CREATE TABLE groups (
                id UUID PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                owner_id UUID REFERENCES users(id),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT group_name_owner_unique UNIQUE (name, owner_id)
            );

            CREATE TABLE passwords (
                id UUID PRIMARY KEY,
                group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
                title VARCHAR(255) NOT NULL,
                description TEXT,
                username VARCHAR(255),
                encrypted_password BYTEA NOT NULL,
                iv BYTEA NOT NULL,
                tag BYTEA NOT NULL,
                url VARCHAR(2048),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                last_accessed TIMESTAMP WITH TIME ZONE,
                expiration_date TIMESTAMP WITH TIME ZONE,
                CONSTRAINT title_group_unique UNIQUE (title, group_id)
            );

            CREATE TABLE group_members (
                group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
                user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                access_level INTEGER NOT NULL CHECK (access_level IN (0, 1, 2)), -- 0: read, 1: write, 2: admin
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (group_id, user_id)
            );

            -- Audit logging
            CREATE TABLE audit_log (
                id UUID PRIMARY KEY,
                user_id UUID REFERENCES users(id),
                action_type VARCHAR(50) NOT NULL,
                entity_type VARCHAR(50) NOT NULL,
                entity_id UUID,
                details JSONB,
                ip_address INET,
                timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );

            -- Indexes
            CREATE INDEX idx_users_username ON users(username);
            CREATE INDEX idx_passwords_group ON passwords(group_id);
            CREATE INDEX idx_group_members_user ON group_members(user_id);
            CREATE INDEX idx_audit_log_user ON audit_log(user_id);
            CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp);
            CREATE INDEX idx_passwords_expiration ON passwords(expiration_date);
        )"
        ,
        // Migration 2: Password history tracking
        R"(
            CREATE TABLE password_history (
                id UUID PRIMARY KEY,
                password_id UUID REFERENCES passwords(id) ON DELETE CASCADE,
                encrypted_password BYTEA NOT NULL,
                iv BYTEA NOT NULL,
                tag BYTEA NOT NULL,
                changed_by UUID REFERENCES users(id),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX idx_password_history_password ON password_history(password_id);
        )"
        ,
        // Migration 3: Session management
        R"(
            CREATE TABLE sessions (
                id UUID PRIMARY KEY,
                user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                token_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                last_activity TIMESTAMP WITH TIME ZONE,
                ip_address INET,
                user_agent TEXT,
                CONSTRAINT unique_token_hash UNIQUE (token_hash)
            );

            -- Rate limiting table
            CREATE TABLE rate_limits (
                id BIGSERIAL PRIMARY KEY,
                key VARCHAR(255) NOT NULL,
                timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );

            -- Session backup codes for MFA recovery
            CREATE TABLE mfa_backup_codes (
                user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                code_hash VARCHAR(255) NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                used_at TIMESTAMP WITH TIME ZONE,
                PRIMARY KEY (user_id, code_hash)
            );

            -- Indexes for session management
            CREATE INDEX idx_sessions_user ON sessions(user_id);
            CREATE INDEX idx_sessions_token_hash ON sessions(token_hash);
            CREATE INDEX idx_sessions_expires ON sessions(expires_at);
            CREATE INDEX idx_rate_limits_key_timestamp ON rate_limits(key, timestamp);
            CREATE INDEX idx_backup_codes_user ON mfa_backup_codes(user_id);
        )"
        ,
        // Migration 4: Password categories and tags
        R"(
            CREATE TABLE categories (
                id UUID PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT category_name_unique UNIQUE (name)
            );

            CREATE TABLE password_categories (
                password_id UUID REFERENCES passwords(id) ON DELETE CASCADE,
                category_id UUID REFERENCES categories(id) ON DELETE CASCADE,
                PRIMARY KEY (password_id, category_id)
            );

            CREATE TABLE tags (
                id UUID PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                CONSTRAINT tag_name_unique UNIQUE (name)
            );

            CREATE TABLE password_tags (
                password_id UUID REFERENCES passwords(id) ON DELETE CASCADE,
                tag_id UUID REFERENCES tags(id) ON DELETE CASCADE,
                PRIMARY KEY (password_id, tag_id)
            );

            CREATE INDEX idx_password_categories ON password_categories(password_id);
            CREATE INDEX idx_password_tags ON password_tags(password_id);
        )"
        ,
        // Migration 5: Session and Security Enhancements
        R"(
            -- Session device tracking
            CREATE TABLE user_devices (
                id UUID PRIMARY KEY,
                user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                device_name VARCHAR(255),
                device_type VARCHAR(50),
                last_ip INET,
                last_login TIMESTAMP WITH TIME ZONE,
                is_trusted BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );

            -- Failed login tracking
            CREATE TABLE failed_login_attempts (
                id BIGSERIAL PRIMARY KEY,
                user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                ip_address INET,
                attempt_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                user_agent TEXT
            );

            -- Security events
            CREATE TABLE security_events (
                id UUID PRIMARY KEY,
                user_id UUID REFERENCES users(id),
                event_type VARCHAR(50) NOT NULL,
                severity VARCHAR(20) NOT NULL,
                description TEXT,
                ip_address INET,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );

            -- Indexes
            CREATE INDEX idx_user_devices_user ON user_devices(user_id);
            CREATE INDEX idx_failed_login_user_time ON failed_login_attempts(user_id, attempt_time);
            CREATE INDEX idx_security_events_user ON security_events(user_id);
            CREATE INDEX idx_security_events_type ON security_events(event_type);
        )"
    };
};

} // namespace db
} // namespace btpv