// src/models/group.hpp
#pragma once

#include <string>
#include <chrono>
#include <boost/uuid/uuid.hpp>

namespace btpv {
namespace models {

struct Group {
    boost::uuids::uuid id;
    std::string name;
    boost::uuids::uuid owner_id;
    std::chrono::system_clock::time_point created_at;
};

} // namespace models
} // namespace btpv