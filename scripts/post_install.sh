#!/bin/bash
# scripts/post_install.sh

# Create btpv user and group if they don't exist
if ! getent group btpv >/dev/null; then
    groupadd -r btpv
fi
if ! getent passwd btpv >/dev/null; then
    useradd -r -g btpv -s /sbin/nologin -d /var/lib/btpv btpv
fi

# Create necessary directories
mkdir -p /var/lib/btpv
mkdir -p /var/log/btpv
mkdir -p /etc/btpv

# Set proper permissions
chown -R btpv:btpv /var/lib/btpv
chown -R btpv:btpv /var/log/btpv
chown -R btpv:btpv /etc/btpv

# Set proper SELinux contexts if SELinux is enabled
if command -v semanage >/dev/null 2>&1; then
    semanage fcontext -a -t httpd_sys_content_t "/var/lib/btpv(/.*)?"
    semanage fcontext -a -t httpd_sys_content_t "/etc/btpv(/.*)?"
    semanage fcontext -a -t httpd_log_t "/var/log/btpv(/.*)?"
    restorecon -R /var/lib/btpv /etc/btpv /var/log/btpv
fi

# Enable and start the service
systemctl daemon-reload
systemctl enable btpv
systemctl start btpv

# Initialize the database if PostgreSQL is installed
if command -v psql >/dev/null 2>&1; then
    sudo -u postgres psql -c "CREATE USER btpv_user WITH PASSWORD 'secure_password';"
    sudo -u postgres psql -c "CREATE DATABASE btpv OWNER btpv_user;"
fi