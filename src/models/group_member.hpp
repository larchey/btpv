// src/models/group_member.hpp
#pragma once

#include <boost/uuid/uuid.hpp>

namespace btpv {
namespace models {

struct GroupMember {
    boost::uuids::uuid group_id;
    boost::uuids::uuid user_id;
    int access_level;  // 0: read, 1: write, 2: admin
};

} // namespace models
} // namespace btpv