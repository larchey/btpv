// src/db/migrations.cpp
#include "migrations.hpp"
#include <boost/log/trivial.hpp>

namespace btpv {
namespace db {

bool DatabaseMigration::create_migrations_table(pqxx::connection& conn) {
    try {
        pqxx::work txn(conn);
        txn.exec(R"(
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            )
        )");
        txn.commit();
        return true;
    }
    catch (const std::exception& ex) {
        BOOST_LOG_TRIVIAL(error) << "Failed to create migrations table: " << ex.what();
        return false;
    }
}

int DatabaseMigration::get_current_version(pqxx::connection& conn) {
    try {
        pqxx::work txn(conn);
        auto result = txn.exec("SELECT MAX(version) FROM schema_migrations");
        txn.commit();
        
        if (result.empty() || result[0][0].is_null()) {
            return 0;
        }
        
        return result[0][0].as<int>();
    }
    catch (const std::exception& ex) {
        BOOST_LOG_TRIVIAL(error) << "Failed to get current schema version: " << ex.what();
        return -1;
    }
}

bool DatabaseMigration::run_migrations(pqxx::connection& conn) {
    try {
        if (!create_migrations_table(conn)) {
            return false;
        }

        int current_version = get_current_version(conn);
        if (current_version < 0) {
            return false;
        }

        for (size_t i = current_version; i < MIGRATIONS.size(); ++i) {
            pqxx::work txn(conn);
            BOOST_LOG_TRIVIAL(info) << "Applying migration " << (i + 1);
            
            try {
                // Execute the migration
                txn.exec(MIGRATIONS[i]);
                
                // Update schema version
                txn.exec_params("INSERT INTO schema_migrations (version) VALUES ($1)",
                              static_cast<int>(i + 1));
                
                txn.commit();
                BOOST_LOG_TRIVIAL(info) << "Successfully applied migration " << (i + 1);
            }
            catch (const std::exception& ex) {
                BOOST_LOG_TRIVIAL(error) << "Migration " << (i + 1) << " failed: " << ex.what();
                return false;
            }
        }

        return true;
    }
    catch (const std::exception& ex) {
        BOOST_LOG_TRIVIAL(error) << "Failed to run migrations: " << ex.what();
        return false;
    }
}

} // namespace db
} // namespace btpv