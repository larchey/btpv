// src/db/sessions/session.hpp
#pragma once

#include <string>
#include <chrono>
#include <boost/uuid/uuid.hpp>

namespace btpv {
namespace models {

struct Session {
    boost::uuids::uuid id;
    boost::uuids::uuid user_id;
    std::string token_hash;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point expires_at;
    std::chrono::system_clock::time_point last_activity;
    std::string ip_address;
    std::string user_agent;
};

} // namespace models
} // namespace btpv