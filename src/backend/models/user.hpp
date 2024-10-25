// src/models/user.hpp
#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <boost/uuid/uuid.hpp>

namespace btpv {
namespace models {

struct User {
    boost::uuids::uuid id;
    std::string username;
    std::string password_hash;
    std::vector<unsigned char> salt;
    std::string mfa_secret;
    std::chrono::system_clock::time_point created_at;
    
    // MFA status
    bool has_mfa_enabled() const { return !mfa_secret.empty(); }
};

} // namespace models
} // namespace btpv