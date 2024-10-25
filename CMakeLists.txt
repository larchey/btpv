cmake_minimum_required(VERSION 3.12)
project(BTPV VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Add compile options
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Werror -pedantic)
endif()

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(Boost 1.67.0 REQUIRED 
    COMPONENTS 
        system 
        filesystem 
        uuid
        program_options
        log
        log_setup
        thread
        property_tree
)
find_package(cpprestsdk REQUIRED)

# PostgreSQL and pqxx handling
find_package(PostgreSQL REQUIRED)

# Find pqxx
find_package(PkgConfig REQUIRED)
pkg_check_modules(PQXX REQUIRED libpqxx)

# If pkg-config didn't find pqxx, try manual paths
if(NOT PQXX_FOUND)
    find_path(PQXX_INCLUDE_DIR
        NAMES pqxx/pqxx
        PATHS
            /usr/include
            /usr/local/include
            /opt/local/include
    )
    
    find_library(PQXX_LIBRARIES
        NAMES pqxx
        PATHS
            /usr/lib
            /usr/local/lib
            /opt/local/lib
            /usr/lib/x86_64-linux-gnu
    )
    
    if(PQXX_INCLUDE_DIR AND PQXX_LIBRARIES)
        set(PQXX_FOUND TRUE)
    endif()
endif()

# Find Argon2
find_path(ARGON2_INCLUDE_DIR
    NAMES argon2.h
    PATHS
        /usr/include
        /usr/local/include
)

find_library(ARGON2_LIBRARY
    NAMES argon2 libargon2
    PATHS
        /usr/lib
        /usr/local/lib
        /usr/lib64
        /usr/local/lib64
)

if(NOT ARGON2_INCLUDE_DIR OR NOT ARGON2_LIBRARY)
    message(FATAL_ERROR "Argon2 library not found. Please install libargon2-dev")
endif()

# Check all required dependencies
if(NOT PQXX_FOUND)
    message(FATAL_ERROR "Could not find libpqxx. Please install libpqxx-dev")
endif()

# Source files
set(BTPV_SOURCES
    src/main.cpp
    src/crypto/encryption.cpp
    src/auth/authentication.cpp
    src/db/database.cpp
    src/db/migrations.cpp
)

# Header files
set(BTPV_HEADERS
    src/models/user.hpp
    src/models/group.hpp
    src/models/password.hpp
    src/models/group_member.hpp
    src/crypto/encryption.hpp
    src/auth/authentication.hpp
    src/db/database.hpp
    src/db/migrations.hpp
)

# Main executable
add_executable(btpv_server ${BTPV_SOURCES} ${BTPV_HEADERS})

# Include directories
target_include_directories(btpv_server
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${Boost_INCLUDE_DIRS} 
        ${PostgreSQL_INCLUDE_DIRS}
        ${PQXX_INCLUDE_DIRS}
        ${ARGON2_INCLUDE_DIR}
        ${Boost_INCLUDE_DIRS}
)

# Link libraries
target_link_libraries(btpv_server
    PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        Boost::system
        Boost::filesystem
        Boost::uuid
        Boost::program_options
        Boost::log
        Boost::log_setup
        Boost::thread
        cpprestsdk::cpprest
        ${PostgreSQL_LIBRARIES}
        ${PQXX_LIBRARIES}
        ${ARGON2_LIBRARY}
        pthread
        stdc++fs
)

# Installation rules
install(TARGETS btpv_server
    RUNTIME DESTINATION bin
)

# Configuration files
install(FILES 
    config/btpv.conf
    DESTINATION etc/btpv
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
)

# Create required directories
install(DIRECTORY
    DESTINATION var/lib/btpv
    DIRECTORY_PERMISSIONS 
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE
)

install(DIRECTORY
    DESTINATION var/log/btpv
    DIRECTORY_PERMISSIONS 
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ GROUP_WRITE GROUP_EXECUTE
        WORLD_READ
)

# Systemd service file
install(FILES systemd/btpv.service
    DESTINATION lib/systemd/system
)

# RPM packaging configuration
set(CPACK_GENERATOR "RPM")
set(CPACK_PACKAGE_NAME "btpv")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_RELEASE "1")
set(CPACK_PACKAGE_CONTACT "Your Name <your.email@example.com>")
set(CPACK_PACKAGE_VENDOR "Your Organization")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Baby Turtle Password Vault - Secure Password Management System")
set(CPACK_RPM_PACKAGE_LICENSE "Proprietary")
set(CPACK_RPM_PACKAGE_GROUP "Applications/System")

# Define RPM dependencies
set(CPACK_RPM_PACKAGE_REQUIRES 
    "openssl >= 1.1.1, boost >= 1.67.0, postgresql-libs >= 10.0, libpqxx >= 6.0, libargon2 >= 20171227"
)

# Pre/Post install scripts
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/scripts/post_install.sh")
set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/scripts/pre_uninstall.sh")

# Don't strip binary (keeps debug symbols)
set(CPACK_RPM_SPEC_MORE_DEFINE "%define __os_install_post %{nil}")

# User/Group creation
set(CPACK_RPM_USER_BINARY_SPECFILE "
%pre
getent group btpv >/dev/null || groupadd -r btpv
getent passwd btpv >/dev/null || useradd -r -g btpv -d /var/lib/btpv -s /sbin/nologin -c 'BTPV Service Account' btpv
exit 0
")

include(CPack)

# Add testing
enable_testing()
add_subdirectory(tests)