#btpv

btpv/
├── CMakeLists.txt                 # Main build configuration
├── src/
│   ├── main.cpp                   # Main application entry
│   ├── models/
│   │   ├── user.hpp
│   │   ├── group.hpp
│   │   ├── password.hpp
│   │   └── group_member.hpp
│   ├── crypto/
│   │   ├── encryption.hpp
│   │   └── encryption.cpp
│   ├── auth/
│   │   ├── authentication.hpp
│   │   └── authentication.cpp
│   └── db/
│       ├── database.hpp
│       ├── database.cpp
│       ├── migrations.hpp
│       └── migrations.cpp
├── config/
│   └── btpv.conf                  # Application configuration
├── scripts/
│   └── post_install.sh           # RPM post-installation script
├── systemd/
│   └── btpv.service              # Systemd service definition
└── tests/                        # Test directory
    └── ...                       # Test files
