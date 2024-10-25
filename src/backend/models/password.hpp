// src/models/password.hpp
#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <boost/uuid/uuid.hpp>

namespace btpv {
namespace models {

struct Password {
    boost::uuids::uuid id;
    boost::uuids::uuid group_id;
    std::string title;
    std::vector<unsigned char> encrypted_password;
    std::vector<unsigned char> iv;
    std::vector<unsigned char> tag;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point updated_at;
};

} // namespace models
} // namespace btpv