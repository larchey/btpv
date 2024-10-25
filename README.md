btpv/
├── CMakeLists.txt
├── src/
│   ├── backend/
│   │   ├── main.cpp *
│   │   ├── api/
│   │   │   ├── controller.hpp *
│   │   │   └── controller.cpp *
│   │   ├── models/
│   │   │   ├── user.hpp *
│   │   │   ├── group.hpp *
│   │   │   ├── password.hpp *
│   │   │   └── group_member.hpp *
│   │   ├── crypto/
│   │   │   ├── encryption.hpp *
│   │   │   └── encryption.cpp *
│   │   ├── auth/
│   │   │   ├── authentication.hpp *
│   │   │   └── authentication.cpp *
│   │   └── db/
│   │       ├── database.hpp *
│   │       ├── database.cpp *
│   │       ├── migrations.hpp *
│   │       └── migrations.cpp *
│   └── frontend/
│       ├── index.html
│       ├── css/
│       │   └── styles.css
│       ├── js/
│       │   ├── app.js
│       │   ├── auth.js
│       │   └── api.js
│       └── assets/
│           └── images/
├── config/
│   ├── btpv.conf *
│   ├── nginx.conf
│   └── systemd/
│       └── btpv.service *
├── scripts/
│   ├── setup/
│   │   ├── install.sh
│   │   ├── configure_nginx.sh
│   │   ├── configure_postgres.sh
│   │   └── generate_certificates.sh
│   └── rpm/
│       ├── btpv.spec
│       └── rpmbuild.sh
├── packaging/
│   ├── rpm/
│   │   └── btpv.spec          # RPM spec file
│   └── systemd/
│       └── btpv.service       # Systemd service file
