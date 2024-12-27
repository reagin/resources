#!/usr/bin/bash

#
#       Trojan & Hysteria Server Installer Script
#
#               Copyright (c) 2024 reagin
#
#   Github: https://github.com/reagin/resources
#
#   In automated environments, you must run as root.
#
#   This only work on amd64 Ubuntu/Debian Linux systems.
#   This script installs Trojan & Hysteria-v2 server to your system.
#

# If an error occurs, exit the script
set -o errexit
# If any subcommand fails, the entire pipeline command fails
set -o pipefail
# Causes trap to catch errors within functions
set -Eeuo pipefail
# When the script exits, delete all temporary files
trap remove_temporary_folder EXIT

# SYSTEM REQUIREMENTS
readonly DEPANDS_PACKAGE=('jq' 'git' 'cron' 'curl' 'lsof' 'socat' 'openssl' 'coreutils' 'build-essential' 'libncurses5-dev')
readonly DEPANDS_COMMAND=('jq' 'git' 'cron' 'curl' 'lsof' 'socat' 'openssl' 'md5sum' 'make' 'tput')

# CONFIG: GLOBAL CONFIGURATION
# Basename of this script
SCRIPT_NAME="$(basename "$0")"

# The user specified scripting option
OPERATION=

# Architecture of current machine
ARCHITECTURE=

# Package manager installer
PACKAGE_INSTALLER=

# Package manager uninstaller
PACKAGE_UNINSTALLER=

# Temporary file directory
TEMPORARY_FILE_DIR=

# Server Domain
SERVER_DOMAIN="${SERVER_DOMAIN:-"gfw.rehug.cc"}"

# Personal Email
PERSONAL_EMAIL="${PERSONAL_EMAIL:-"reagin@163.com"}"

# Paths to install systemd files
SYSTEMD_SERVICES_DIR="/etc/systemd/system"

# CONFIG: ACME.SH CONFIGURATION
# Directory to store acme cert
ACME_CERT_DIR="${ACME_CERT_DIR:-"/etc/acme"}"

# Set the default CA Server of ACME.SH
ACME_CA_SERVER="letsencrypt"

# Private key path
PRIVATE_KEY_PATH=

# Public pem path
PUBLIC_PEM_PATH=

# CONFIG: NGINX CONFIGURATION
# Directory to store nginx configs
NGINX_CONFIG_DIR=

# CONFIG: TROJAN CONFIGURATION
# Path for installing trojan executable
TROJAN_EXECUTABLE_PATH="/usr/local/bin/trojan"

# Directory for trojan to run
TROJAN_WORKING_DIR="/var/lib/trojan"

# Directory to store trojan config file
TROJAN_CONFIG_DIR="/etc/trojan"

# User specified listening port
TROJAN_LISTEN_PORT="${TROJAN_LISTEN_PORT:-"8000"}"

# Password for authenticate
TROJAN_AUTH_PASSWORD="${TROJAN_AUTH_PASSWORD:-}"

# Trojan tag_name obtained through GitHub API
TROJAN_TAG_NAME=

# CONFIG: HYSTERIA CONFIGURATION
# Path for installing hysteria executable
HYSTERIA_EXECUTABLE_PATH="/usr/local/bin/hysteria"

# Directory for hysteria to run
HYSTERIA_WORKING_DIR="/var/lib/hysteria"

# Directory to store hysteria config file
HYSTERIA_CONFIG_DIR="/etc/hysteria"

# User specified listening port
HYSTERIA_LISTEN_PORT="${HYSTERIA_LISTEN_PORT:-"8080"}"

# User specified listening port hopping range
HYSTERIA_HOPPING_RANGE="${HYSTERIA_HOPPING_RANGE:-"32768-49151"}"

# Password for authenticate
HYSTERIA_AUTH_PASSWORD="${HYSTERIA_AUTH_PASSWORD:-}"

# Password for masquerade
HYSTERIA_OBFS_PASSWORD="${HYSTERIA_OBFS_PASSWORD:-}"

# Hysteria tag_name obtained through GitHub API
HYSTERIA_TAG_NAME=

mhead() {
    echo -ne "$SCRIPT_NAME: "
}

mnote() {
    echo -ne "$(tput setaf 8)${1:-}$(tput sgr0)"
    if [[ -z "${2:-}" ]]; then
        echo ""
    fi
}

merror() {
    echo -ne "$(tput setaf 1)${1:-}$(tput sgr0)"
    if [[ -z "${2:-}" ]]; then
        echo ""
    fi
}

msuccess() {
    echo -ne "$(tput setaf 2)${1:-}$(tput sgr0)"
    if [[ -z "${2:-}" ]]; then
        echo ""
    fi
}

mwarning() {
    echo -ne "$(tput setaf 3)${1:-}$(tput sgr0)"
    if [[ -z "${2:-}" ]]; then
        echo ""
    fi
}

show_argument_error_and_exit() {
    mhead && merror "${1:-"error"}"
    mhead && merror "Try \"$0 --help\" for usage" && exit 99
}

has_command() {
    type -P "$1" >/dev/null 2>&1
}

has_prefix() {
    if [[ -z "$2" ]]; then
        return 0
    elif [[ -z "$1" ]]; then
        return 1
    fi

    [[ "x$1" != "x${1#"$2"}" ]]
}

install_content() {
    local _tmpfile
    local _flags="$1"
    local _content="$2"
    local _destination="$3"
    local _overwrite="${4:-}"

    _tmpfile=$(mktemp -p "$TEMPORARY_FILE_DIR")

    [[ -n "$_content" ]] && echo "$_content" >"$_tmpfile"

    mhead && mnote "Installing $_destination ... " "true"

    if [[ -z "$_overwrite" && -e "$_destination" ]]; then
        mwarning "existed"
    elif install "$_flags" "$_tmpfile" "$_destination"; then
        msuccess "done"
    fi
}

remove_content() {
    local _destination="$1"

    mhead && mnote "Removing " "true"

    if [[ "$_destination" == '/' ]]; then
        mnote "$_destination ... " "true" && merror "error"
    elif [[ ! -e "$_destination" ]]; then
        mnote "$_destination ... " "true" && merror "not existed"
    elif [[ -f "$_destination" ]]; then
        mnote "file: $_destination ... " "true" && rm -rf "$_destination" && msuccess "done"
    elif [[ -d "$_destination" ]]; then
        mnote "directory: $_destination ... " "true" && rm -rf "$_destination" && msuccess "done"
    fi
}

generate_random_password() {
    local _password

    _password=$(dd if=/dev/random bs=32 count=1 status=none | tr -d '\0')
    echo -n "$_password" | md5sum | sed 's/ .*//'
}

get_proxy_name() {
    local _region
    local _country_code
    local _country_flag

    declare -A country_flags=(
        ["US"]="🗽"
        ["HK"]="🐉"
        ["JP"]="🌸"
    )

    [[ ! -f "geoip.json" ]] && curl -fsSL "https://api.ip.sb/geoip" -A Mozilla -o "geoip.json"

    _region=$(jq -r '.region' <"geoip.json")
    _country_code=$(jq -r '.country_code' <"geoip.json")
    _country_flag=${country_flags[$_country_code]:-"😢"}

    [[ -n "$_region" && -n "$_country_code" ]] && echo "$_country_flag $_region"
}

check_permission() {
    if [[ "$EUID" -eq '0' ]]; then
        mhead && mnote "Run script with root" && return
    fi

    mhead && merror "Please run this script with root" && exit 1
}

check_architecture() {
    case "$(uname -m)" in
    'amd64' | 'x86_64')
        ARCHITECTURE='amd64'
        ;;
    *)
        mhead && merror "The architecture '$(uname -a)' is not supported" && exit 2
        ;;
    esac
}

check_package_installer() {
    if [[ -n "$PACKAGE_INSTALLER" ]]; then
        return
    elif has_command apt; then
        PACKAGE_INSTALLER='apt -y install'
        PACKAGE_UNINSTALLER='apt -y purge' && return
    elif has_command dnf; then
        PACKAGE_INSTALLER='dnf -y install'
        PACKAGE_UNINSTALLER='dnf -y remove --purge' && return
    elif has_command yum; then
        PACKAGE_INSTALLER='yum -y install'
        PACKAGE_UNINSTALLER='yum -y remove --purge' && return
    elif has_command zypper; then
        PACKAGE_INSTALLER='zypper install -y --no-recommends'
        PACKAGE_UNINSTALLER='zypper remove -y --clean-deps' && return
    elif has_command pacman; then
        PACKAGE_INSTALLER='pacman -S --noconfirm'
        PACKAGE_UNINSTALLER='pacman -Rns --noconfirm' && return
    fi

    mhead && merror "Not find the package installer" && exit 2
}

# TODO: In the future, support more linux distribution
check_operating_system() {
    local _lsb_dist

    if [[ "$(uname)" != "Linux" ]]; then
        mhead && merror "This script only supports ubuntu/debian Linux" && exit 2
    fi

    # shellcheck source=/dev/null
    source /etc/os-release

    _lsb_dist=$( ([ -n "${ID}" ] && echo "${ID}") || ([ -n "${ID_LIKE}" ] && echo "${ID_LIKE}"))

    case $_lsb_dist in
    *ubuntu*) ;;
    *debian*) ;;
    *)
        mhead && merror "This script only supports ubuntu/debian Linux" && exit 2
        ;;
    esac

    check_architecture && check_package_installer

    mhead && mnote "Run script in ${_lsb_dist}/Linux - ${ARCHITECTURE}"
    mhead && mnote "Package installer is '${PACKAGE_INSTALLER} < package_name >'"
}

check_dependent_software() {
    local _cmd
    local _package_name

    echo && mhead && mnote "Check necessary dependencies..."

    for ((i = 0; i < ${#DEPANDS_COMMAND[@]}; i++)); do
        _cmd=${DEPANDS_COMMAND[i]}
        _package_name=${DEPANDS_PACKAGE[i]}
        if ! has_command "$_cmd"; then
            merror "    - ${_package_name} not exist"
            mnote "    + installing missing dependence ${_package_name}..."
            if $PACKAGE_INSTALLER "$_package_name" >/dev/null 2>&1; then
                msuccess "    + install ${_package_name} successfully"
            else
                mhead && merror "Cannot install ${_package_name} with detected package manager, Please install it manually" && exit 3
            fi
        else
            msuccess "    * ${_package_name} is installed"
        fi
    done

    mhead && mnote "All dependencies are installed" && echo
}

# NOTE: Create a temporary directory and temporarily save the downloaded file
create_temporary_folder() {
    TEMPORARY_FILE_DIR=$(mktemp -d)

    if ! pushd "$TEMPORARY_FILE_DIR" >/dev/null 2>&1; then
        mhead && merror "Change temporary directory failed" && exit 4
    fi
}

remove_temporary_folder() {
    if [[ -d "$TEMPORARY_FILE_DIR" ]]; then
        popd >/dev/null 2>&1
        rm -rf "$TEMPORARY_FILE_DIR"
    fi
}

# NOTE: Functions for acme.sh
install_acme() {
    mhead && mnote "Installing acme.sh ... " "true"

    if [[ -d "$HOME/.acme.sh" ]]; then
        mwarning "existed" && return
    elif has_command "acme.sh"; then
        merror "error"
        mhead && merror "Please uninstall acme.sh manually" && exit 11
    fi

    git clone --depth 1 https://github.com/acmesh-official/acme.sh.git >/dev/null 2>&1

    echo && echo -e '\n# source acme.sh.env' >>"$HOME/.bashrc"

    pushd acme.sh >/dev/null 2>&1 && ./acme.sh --install -m "$PERSONAL_EMAIL" && popd >/dev/null 2>&1

    "$HOME/.acme.sh/acme.sh" --upgrade --auto-upgrade
    "$HOME/.acme.sh/acme.sh" --set-default-ca --server "$ACME_CA_SERVER"
}

uninstall_acme() {
    mhead && mnote "Removing acme.sh ... " "true"

    crontab -l 2>/dev/null | grep -v 'acme.sh' || true | crontab -
    sed -i '/^$/N;/\n# source acme\.sh\.env/{N;d}' "$HOME/.bashrc"
    rm -rf "$HOME/.acme.sh"

    msuccess "done"
}

# NOTE: Functions for cert
install_cert() {
    if lsof -i :80 >/dev/null; then
        for _pid in $(lsof -t -i :80); do
            _process=$(ps -p "$_pid" -o comm= | tail -n 1)
            mhead && merror "Port 80 is in use by process $_process (PID: $_pid)"
        done
        mhead && merror "Please free the port and try again." && exit 21
    elif [[ -e "$PRIVATE_KEY_PATH" && -e "$PUBLIC_PEM_PATH" ]]; then
        mhead && mnote "Installing $PUBLIC_PEM_PATH ..." "true" && mwarning "skip"
        mhead && mnote "Installing $PRIVATE_KEY_PATH ..." "true" && mwarning "skip" && return
    fi

    install_content -Dm644 "" "$PUBLIC_PEM_PATH" "true"
    install_content -Dm600 "" "$PRIVATE_KEY_PATH" "true"

    "$HOME/.acme.sh/acme.sh" --issue -d "$SERVER_DOMAIN" --standalone
    "$HOME/.acme.sh/acme.sh" --install-cert -d "$SERVER_DOMAIN" \
        --key-file "$PRIVATE_KEY_PATH" \
        --fullchain-file "$PUBLIC_PEM_PATH"
}

uninstall_cert() {
    remove_content "${ACME_CERT_DIR:?}/${SERVER_DOMAIN:?}"
}

# NOTE: Functions for nginx
install_nginx_binary() {
    mhead && mnote "Installing nginx ... " "true"

    if has_command nginx; then
        mwarning "existed"
        mhead && merror "For your data security, nginx needs to uninstall manually first" && exit 31
    elif $PACKAGE_INSTALLER nginx >/dev/null 2>&1; then
        msuccess "done"
    else
        merror "error" && exit 32
    fi
}

delete_nginx_default() {
    NGINX_CONFIG_DIR="$(dirname "$(nginx -V 2>&1 | grep -oP '(?<=--conf-path=)[^\s]+')")"

    remove_content "/var/www/html"
    remove_content "$NGINX_CONFIG_DIR/sites-enabled"
    remove_content "$NGINX_CONFIG_DIR/sites-available"
}

generate_nginx_conf() {
    cat <<EOF
user                 root;
pid                  /run/nginx.pid;
worker_processes     auto;
worker_rlimit_nofile 65535;

# Load modules
include              $NGINX_CONFIG_DIR/modules-enabled/*.conf;

events {
    multi_accept       on;
    worker_connections 65535;
}

http {
    charset                utf-8;
    sendfile               on;
    tcp_nopush             on;
    tcp_nodelay            on;
    server_tokens          off;
    log_not_found          off;
    types_hash_max_size    2048;
    types_hash_bucket_size 64;
    client_max_body_size   16M;

    # MIME
    include                mime.types;
    default_type           application/octet-stream;

    # Logging
    access_log             off;
    error_log              /dev/null;

    # SSL
    ssl_session_timeout    1d;
    ssl_session_cache      shared:SSL:10m;
    ssl_session_tickets    off;

    # Diffie-Hellman parameter for DHE ciphersuites
    ssl_dhparam            $NGINX_CONFIG_DIR/dhparam.pem;

    # Mozilla Intermediate configuration
    ssl_protocols          TLSv1.2 TLSv1.3;
    ssl_ciphers            ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

    # OCSP Stapling
    ssl_stapling           on;
    ssl_stapling_verify    on;
    resolver               1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 208.67.222.222 208.67.220.220 valid=60s;
    resolver_timeout       2s;

    # Load configs
    include                $NGINX_CONFIG_DIR/conf.d/*.conf;
    include                $NGINX_CONFIG_DIR/sites-enabled/*;
}
EOF
}

generate_domain_conf() {
    cat <<EOF
server {
    listen              443 ssl http2;
    listen              [::]:443 ssl http2;
    server_name         $SERVER_DOMAIN;
    root                /var/www/$SERVER_DOMAIN/public;

    # SSL
    ssl_certificate     $PUBLIC_PEM_PATH;
    ssl_certificate_key $PRIVATE_KEY_PATH;

    # security
    include             snippets/security.conf;

    # logging
    access_log          /var/log/nginx/access.log combined buffer=512k flush=1m;
    error_log           /var/log/nginx/error.log warn;

    # additional config
    include             snippets/general.conf;
}

# subdomains redirect
server {
    listen              443 ssl http2;
    listen              [::]:443 ssl http2;
    server_name         *.$SERVER_DOMAIN;

    # SSL
    ssl_certificate     $PUBLIC_PEM_PATH;
    ssl_certificate_key $PRIVATE_KEY_PATH;
    return              301 https://$SERVER_DOMAIN\$request_uri;
}

# HTTP redirect
server {
    listen      80;
    listen      [::]:80;
    server_name .$SERVER_DOMAIN;
    return      301 https://$SERVER_DOMAIN\$request_uri;
}
EOF
}

generate_security_conf() {
    cat <<EOF
# security headers
add_header X-XSS-Protection          "1; mode=block" always;
add_header X-Content-Type-Options    "nosniff" always;
add_header Referrer-Policy           "origin-when-cross-origin" always;
add_header Content-Security-Policy   "default-src 'self' http: https: ws: wss: data: blob: 'unsafe-inline'; frame-ancestors 'self';" always;
add_header Permissions-Policy        "interest-cohort=()" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# . files
location ~ /\.(?!well-known) {
    deny all;
}
EOF
}

generate_general_conf() {
    cat <<EOF
# favicon.ico
location = /favicon.ico {
    log_not_found off;
}

# robots.txt
location = /robots.txt {
    log_not_found off;
}

# assets, media
location ~* \.(?:css(\.map)?|js(\.map)?|jpe?g|png|gif|ico|cur|heic|webp|tiff?|mp3|m4a|aac|ogg|midi?|wav|mp4|mov|webm|mpe?g|avi|ogv|flv|wmv)$ {
    expires 7d;
}

# svg, fonts
location ~* \.(?:svgz?|ttf|ttc|otf|eot|woff2?)$ {
    add_header Access-Control-Allow-Origin "*";
    expires    7d;
}

# gzip
gzip            on;
gzip_vary       on;
gzip_proxied    any;
gzip_comp_level 6;
gzip_types      text/plain text/css text/xml application/json application/javascript application/rss+xml application/atom+xml image/svg+xml;
EOF
}

install_nginx_config() {
    NGINX_CONFIG_DIR="$(dirname "$(nginx -V 2>&1 | grep -oP '(?<=--conf-path=)[^\s]+')")"

    install -dm755 "$NGINX_CONFIG_DIR/sites-enabled"

    install_content -Dm644 "$(generate_nginx_conf)" "$NGINX_CONFIG_DIR/nginx.conf" "true"
    install_content -Dm644 "$(generate_security_conf)" "$NGINX_CONFIG_DIR/snippets/security.conf" "true"
    install_content -Dm644 "$(generate_general_conf)" "$NGINX_CONFIG_DIR/snippets/general.conf" "true"
    install_content -Dm644 "$(generate_domain_conf)" "$NGINX_CONFIG_DIR/sites-available/$SERVER_DOMAIN.conf" "true"

    mhead && mnote "Installing $NGINX_CONFIG_DIR/dhparam.pem ... " "true"
    openssl dhparam -out "$NGINX_CONFIG_DIR/dhparam.pem" 2048 >/dev/null 2>&1
    msuccess "done"

    ln -s "$NGINX_CONFIG_DIR/sites-available/$SERVER_DOMAIN.conf" "$NGINX_CONFIG_DIR/sites-enabled/$SERVER_DOMAIN.conf" >/dev/null 2>&1
}

download_nginx_website() {
    local _website_url="$1"
    local _destination="$2"

    mhead && mnote "Downloading fake website files: $_website_url ... " "true"

    if ! curl -fsSL "$_website_url" -o "$_destination" || [[ ! -s "$_destination" ]]; then
        merror "error"
        mhead && merror "Download failed or file size is zero, please check your network and try again." && exit 33
    fi

    msuccess "done"
}

install_nginx_website() {
    download_nginx_website "https://raw.githubusercontent.com/reagin/resources/refs/heads/main/template/rehug.cc.tar.gz" "rehug.cc.tar.gz"

    mhead && mnote "Installing fake website to /var/www/$SERVER_DOMAIN/public ... " "true"

    install -dm755 "/var/www/$SERVER_DOMAIN/public"

    tar -xzf "rehug.cc.tar.gz" -C "/var/www/$SERVER_DOMAIN/public"

    chown -R root:root /var/www/
    chmod -R 644 "/var/www/$SERVER_DOMAIN/public"

    msuccess "done"
}

install_nginx() {
    install_nginx_binary
    delete_nginx_default
    install_nginx_config
    install_nginx_website

    systemctl daemon-reload
    systemctl enable nginx.service >/dev/null 2>&1
}

uninstall_nginx() {
    mhead && mnote "Removing nginx ... " "true"

    if has_command nginx; then
        NGINX_CONFIG_DIR="$(dirname "$(nginx -V 2>&1 | grep -oP '(?<=--conf-path=)[^\s]+')")"
    else
        merror "error"
        mhead && merror "Didn't find nginx, please delete nginx manually ..." && exit 34
    fi

    if $PACKAGE_UNINSTALLER nginx >/dev/null 2>&1; then
        msuccess "done"
        remove_content "$NGINX_CONFIG_DIR"
        remove_content "/var/www/$SERVER_DOMAIN"
    else
        merror "error"
        mhead && merror "Please delete nginx manually ..." && exit 35
    fi
}

# NOTE: Functions for trojan
install_trojan_dir() {
    install -dm755 "$TROJAN_CONFIG_DIR"
    install -dm755 "$TROJAN_WORKING_DIR"
    install -dm755 "$SYSTEMD_SERVICES_DIR/trojan-server.service.d"
}

get_trojan_latest_version() {
    mhead && mnote "Trojan latest version is: " "true"

    if curl -fsSL "https://api.github.com/repos/trojan-gfw/trojan/releases/latest" -o "trojan_version.json"; then
        TROJAN_TAG_NAME=$(jq -r '.tag_name' <"trojan_version.json")

        if [[ -n "$TROJAN_TAG_NAME" ]]; then
            msuccess "${TROJAN_TAG_NAME#v}" && return
        fi

        merror "error"
    fi

    mhead && merror "Failed to get the latest trojan version from GitHub API, please check your network and try again." && exit 41
}

download_trojan() {
    local _destination="$1"
    local _download_url="https://github.com/trojan-gfw/trojan/releases/download/$TROJAN_TAG_NAME/trojan-${TROJAN_TAG_NAME#v}-linux-$ARCHITECTURE.tar.xz"

    mhead && mnote "Downloading $_destination: $_download_url ... " "true"

    if ! curl -fsSL "$_download_url" -o "$_destination" || [[ ! -s "$_destination" ]]; then
        merror "error"
        mhead && merror "Download failed or file size is zero, please check your network and try again." && exit 42
    fi

    msuccess "done"
}

install_trojan_binary() {
    if [[ -z "$TROJAN_TAG_NAME" ]]; then
        get_trojan_latest_version
    fi

    download_trojan "trojan-linux-$ARCHITECTURE.tar.xz"

    tar -xf "trojan-linux-$ARCHITECTURE.tar.xz" >/dev/null 2>&1

    mhead && mnote "Installing $TROJAN_EXECUTABLE_PATH ... " "true"

    if install -Dm755 "trojan/trojan" "$TROJAN_EXECUTABLE_PATH"; then
        msuccess "done"
    else
        merror "error" && exit 43
    fi
}

generate_trojan_config() {
    cat <<EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": $TROJAN_LISTEN_PORT,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": [
        "$TROJAN_AUTH_PASSWORD"
    ],
    "log_level": 2,
    "ssl": {
        "key": "$PRIVATE_KEY_PATH",
        "cert": "$PUBLIC_PEM_PATH",
        "key_password": "",
        "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384",
        "cipher_tls13": "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
        "prefer_server_cipher": true,
        "alpn": [
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": false,
        "session_timeout": 600,
        "plain_http_response": "",
        "curves": "",
        "dhparam": ""
    },
    "tcp": {
        "no_delay": true,
        "keep_alive": true,
        "fast_open": false,
        "fast_open_qlen": 20
    },
    "mysql": {
        "enabled": false,
        "server_addr": "127.0.0.1",
        "server_port": 3306,
        "database": "trojan",
        "username": "trojan",
        "password": ""
    }
}
EOF
}

install_trojan_config() {
    TROJAN_AUTH_PASSWORD=${TROJAN_AUTH_PASSWORD:-"$(generate_random_password)"}
    install_content -Dm644 "$(generate_trojan_config)" "$TROJAN_CONFIG_DIR/config.json"
}

generate_trojan_systemd_service() {
    cat <<EOF
[Unit]
Description=Trojan Server Service
After=network.target network-online.target nss-lookup.target mysql.service mariadb.service mysqld.service

[Service]
User=root
Group=root
Type=simple
StandardError=journal
WorkingDirectory=$TROJAN_WORKING_DIR
ExecStart=$TROJAN_EXECUTABLE_PATH --config $TROJAN_CONFIG_DIR/$1.json
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=1s

[Install]
WantedBy=multi-user.target
EOF
}

generate_trojan_systemd_priority() {
    cat <<EOF
[Service]
CPUSchedulingPolicy=rr
CPUSchedulingPriority=99
EOF
}

install_trojan_systemd() {
    install_content -Dm644 "$(generate_trojan_systemd_service 'config')" "$SYSTEMD_SERVICES_DIR/trojan-server.service" "true"
    install_content -Dm644 "$(generate_trojan_systemd_service '%i')" "$SYSTEMD_SERVICES_DIR/trojan-server@.service" "true"
    install_content -Dm644 "$(generate_trojan_systemd_priority)" "$SYSTEMD_SERVICES_DIR/trojan-server.service.d/priority.conf" "true"
}

install_trojan() {
    install_trojan_dir
    install_trojan_binary
    install_trojan_config
    install_trojan_systemd

    systemctl daemon-reload
    systemctl enable trojan-server.service >/dev/null 2>&1
}

get_trojan_services() {
    systemctl list-units --state=active --plain --no-legend |
        grep -o "trojan-server@*[^\s]*.service" || true
}

stop_trojan_services() {
    mhead && mnote "Stopping trojan running service..."

    for service in $(get_trojan_services); do
        mnote "    * Stopping $service ... " "true"

        systemctl stop "$service" >/dev/null 2>&1
        systemctl disable "$service" >/dev/null 2>&1

        msuccess "done"
    done
}

remove_trojan_configs() {
    for _path in \
        "$TROJAN_CONFIG_DIR" \
        "$TROJAN_WORKING_DIR" \
        "$SYSTEMD_SERVICES_DIR/trojan-server.service.d" \
        "$SYSTEMD_SERVICES_DIR/trojan-server@.service" \
        "$SYSTEMD_SERVICES_DIR/trojan-server.service" \
        "$TROJAN_EXECUTABLE_PATH"; do
        remove_content "$_path"
    done
}

uninstall_trojan() {
    stop_trojan_services
    remove_trojan_configs

    systemctl daemon-reload
}

# NOTE: Functions for trojan
install_hysteria_dir() {
    install -dm755 "$HYSTERIA_CONFIG_DIR"
    install -dm755 "$HYSTERIA_WORKING_DIR"
    install -dm755 "$SYSTEMD_SERVICES_DIR/hysteria-server.service.d"
}

get_hysteria_latest_version() {
    mhead && mnote "Hysteria latest version is: " "true"

    if curl -fsSL "https://api.github.com/repos/apernet/hysteria/releases/latest" -o "hysteria_version.json"; then
        HYSTERIA_TAG_NAME=$(jq -r '.tag_name' <"hysteria_version.json")

        if [[ -n "$HYSTERIA_TAG_NAME" ]]; then
            msuccess "${HYSTERIA_TAG_NAME#app/v}" && return
        fi

        merror "error"
    fi

    mhead && merror "Failed to get the latest hysteria version from GitHub API, please check your network and try again." && exit 51
}

download_hysteria() {
    local _destination="$1"
    local _download_url="https://github.com/apernet/hysteria/releases/download/$HYSTERIA_TAG_NAME/hysteria-linux-$ARCHITECTURE"

    mhead && mnote "Downloading hysteria binary: $_download_url ... " "true"

    if ! curl -fsSL "$_download_url" -o "$_destination" || [[ ! -s "$_destination" ]]; then
        merror "error"
        mhead && merror "Download failed or file size is zero, please check your network and try again." && exit 52
    fi

    msuccess "done" && return
}

install_hysteria_binary() {
    [[ -z "$HYSTERIA_TAG_NAME" ]] && get_hysteria_latest_version

    download_hysteria "hysteria-linux-$ARCHITECTURE"

    mhead && mnote "Installing $HYSTERIA_EXECUTABLE_PATH ... " "true"

    if install -Dm755 "hysteria-linux-$ARCHITECTURE" "$HYSTERIA_EXECUTABLE_PATH"; then
        msuccess "done"
    else
        merror "error" && exit 53
    fi
}

generate_hysteria_config() {
    cat <<EOF
listen: :$HYSTERIA_LISTEN_PORT

speedTest: true

tls: 
  key: $PRIVATE_KEY_PATH
  cert: $PUBLIC_PEM_PATH
  sniGuard: strict

auth:
    type: password
    password: $HYSTERIA_AUTH_PASSWORD

obfs:
    type: salamander
    salamander:
        password: $HYSTERIA_OBFS_PASSWORD

masquerade:
    type: proxy
    proxy:
        url: https://$SERVER_DOMAIN
        rewriteHost: true
EOF
}

install_hysteria_config() {
    HYSTERIA_AUTH_PASSWORD=${HYSTERIA_AUTH_PASSWORD:-"$(generate_random_password)"}
    HYSTERIA_OBFS_PASSWORD=${HYSTERIA_OBFS_PASSWORD:-"$(generate_random_password)"}
    install_content -Dm644 "$(generate_hysteria_config)" "$HYSTERIA_CONFIG_DIR/config.yaml"
}

generate_hysteria_systemd_service() {
    cat <<EOF
[Unit]
Description=Hysteria Server Service
After=network.target

[Service]
User=root
Group=root
Type=simple
StandardError=journal
WorkingDirectory=$HYSTERIA_WORKING_DIR
ExecStart=$HYSTERIA_EXECUTABLE_PATH server --config $HYSTERIA_CONFIG_DIR/$1.yaml
Environment=HYSTERIA_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
}

generate_hysteria_systemd_priority() {
    cat <<EOF
[Service]
CPUSchedulingPolicy=rr
CPUSchedulingPriority=99
EOF
}

install_hysteria_systemd() {
    install_content -Dm644 "$(generate_hysteria_systemd_service 'config')" "$SYSTEMD_SERVICES_DIR/hysteria-server.service" "true"
    install_content -Dm644 "$(generate_hysteria_systemd_service '%i')" "$SYSTEMD_SERVICES_DIR/hysteria-server@.service" "true"
    install_content -Dm644 "$(generate_hysteria_systemd_priority)" "$SYSTEMD_SERVICES_DIR/hysteria-server.service.d/priority.conf" "true"
}

install_hysteria_porthopping() {
    mhead && mnote "Installing hysteria porthopping ... " "true"

    cat <<EOF | sudo tee -a /etc/nftables.conf >/dev/null
# hysteria_porthopping config
define PORT_RANGE = $HYSTERIA_HOPPING_RANGE
define INGRESS_INTERFACE = "eth0"
define HYSTERIA_SERVER_PORT = $HYSTERIA_LISTEN_PORT

table inet hysteria_porthopping {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        iifname \$INGRESS_INTERFACE udp dport \$PORT_RANGE counter redirect to :\$HYSTERIA_SERVER_PORT
    }
}
EOF

    msuccess "done"
}

install_hysteria() {
    install_hysteria_dir
    install_hysteria_binary
    install_hysteria_config
    install_hysteria_systemd
    install_hysteria_porthopping

    systemctl daemon-reload
    systemctl enable nftables.service >/dev/null 2>&1
    systemctl enable hysteria-server.service >/dev/null 2>&1
}

get_hysteria_services() {
    systemctl list-units --state=active --plain --no-legend |
        grep -o "hysteria-server@*[^\s]*.service" || true
}

stop_hysteria_services() {
    mhead && mnote "Stopping hysteria running service..."

    for service in $(get_hysteria_services); do
        mnote "    * Stopping $service ... " "true"

        systemctl stop "$service" >/dev/null 2>&1
        systemctl disable "$service" >/dev/null 2>&1

        msuccess "done"
    done
}

remove_hysteria_configs() {
    for _path in \
        "$HYSTERIA_CONFIG_DIR" \
        "$HYSTERIA_WORKING_DIR" \
        "$SYSTEMD_SERVICES_DIR/hysteria-server.service.d" \
        "$SYSTEMD_SERVICES_DIR/hysteria-server@.service" \
        "$SYSTEMD_SERVICES_DIR/hysteria-server.service" \
        "$HYSTERIA_EXECUTABLE_PATH"; do
        remove_content "$_path"
    done
}

remove_hysteria_porthopping() {
    mhead && mnote "Removing hysteria port hopping..."

    sudo sed -i '/# hysteria_porthopping config/,+11d' /etc/nftables.conf

    msuccess "done"
}

uninstall_hysteria() {
    stop_hysteria_services
    remove_hysteria_configs
    remove_hysteria_porthopping

    systemctl daemon-reload
}

# NOTE: Update the reload command of acme.sh
update_reloadcmd() {
    local reload_cmd
    local new_reload_cmd

    mhead && mnote "Current reload command: " "true"

    if [[ -f "$HOME/.acme.sh/acme.sh" ]]; then
        reload_cmd=$("$HOME/.acme.sh/acme.sh" --info -d "$SERVER_DOMAIN" | grep "Le_ReloadCmd=" | cut -d '=' -f 2-)
        msuccess "$reload_cmd"
    else
        merror "error"
        mhead && merror "Not find instruction: $HOME/.acme.sh/acme.sh" && exit 61
    fi

    read -rep "Enter new reload command: " new_reload_cmd

    "$HOME/.acme.sh/acme.sh" --install-cert -d "$SERVER_DOMAIN" \
        --key-file "$PRIVATE_KEY_PATH" \
        --fullchain-file "$PUBLIC_PEM_PATH" \
        --reloadcmd "$new_reload_cmd"
}

# NOTE: Get the configuration in the current system
get_trojan_auth_password() {
    if [[ -f "$TROJAN_CONFIG_DIR/config.json" ]]; then
        TROJAN_AUTH_PASSWORD=$(jq -r '.password[0]' "$TROJAN_CONFIG_DIR/config.json")
    else
        TROJAN_AUTH_PASSWORD=""
    fi
}

get_hysteria_auth_password() {
    if [[ -f "$HYSTERIA_CONFIG_DIR/config.yaml" ]]; then
        HYSTERIA_AUTH_PASSWORD=$(
            sed -n '/^[[:space:]]*auth:/,/^[^[:space:]]/ {
                        s/^[[:space:]]*password:[[:space:]]*\(.*\)/\1/p
            }' "$HYSTERIA_CONFIG_DIR/config.yaml"
        )
    else
        HYSTERIA_AUTH_PASSWORD=""
    fi
}

get_hysteria_obfs_password() {
    if [[ -f "$HYSTERIA_CONFIG_DIR/config.yaml" ]]; then
        HYSTERIA_OBFS_PASSWORD=$(
            sed -n '/^[[:space:]]*obfs:/,/^[^[:space:]]/ {
                        /^[[:space:]]*salamander:/,/^[^[:space:]]/ {
                            s/^[[:space:]]*password:[[:space:]]*\(.*\)/\1/p
                }
            }' "$HYSTERIA_CONFIG_DIR/config.yaml"
        )
    else
        HYSTERIA_OBFS_PASSWORD=""
    fi
}

# NOTE: Get the subscription href in the current system
generate_mihomo_subscription() {
    local _yaml_name
    local _mihomo_dir="/var/www/$SERVER_DOMAIN/public/mihomo/"

    if [[ -d "$_mihomo_dir" ]]; then
        _yaml_name=$(find "$_mihomo_dir" -type f -name "*.yaml" -exec basename {} \;)
    fi

    _yaml_name="${_yaml_name:-"$(generate_random_password).yaml"}"

    rm -rf "$_mihomo_dir"
    install -dm755 "$_mihomo_dir"

    curl -fsSL "https://raw.githubusercontent.com/reagin/resources/refs/heads/main/template/mihomo.yaml" -o "$_mihomo_dir/$_yaml_name"

    [[ -z "$HYSTERIA_AUTH_PASSWORD" ]] && sed -i "53d" "$_mihomo_dir/$_yaml_name"
    [[ -z "$TROJAN_AUTH_PASSWORD" ]] && sed -i "52d" "$_mihomo_dir/$_yaml_name"

    [[ -z "$HYSTERIA_AUTH_PASSWORD" ]] && sed -i "36,47d" "$_mihomo_dir/$_yaml_name"
    [[ -z "$TROJAN_AUTH_PASSWORD" ]] && sed -i "29,35d" "$_mihomo_dir/$_yaml_name"

    sed -i "s|<<SERVER_DOMAIN>>|${SERVER_DOMAIN}|g" "$_mihomo_dir/$_yaml_name"

    if [[ -n "$HYSTERIA_AUTH_PASSWORD" ]]; then
        sed -i "s|<<HYSTERIA_NAME>>|$(get_proxy_name | sed 's/[&/\]/\\&/g') Hysteria|g" "$_mihomo_dir/$_yaml_name"
        sed -i "s|<<HYSTERIA_LISTEN_PORT>>|${HYSTERIA_LISTEN_PORT}|g" "$_mihomo_dir/$_yaml_name"
        sed -i "s|<<HYSTERIA_HOPPING_RANGE>>|${HYSTERIA_HOPPING_RANGE}|g" "$_mihomo_dir/$_yaml_name"
        sed -i "s|<<HYSTERIA_AUTH_PASSWORD>>|${HYSTERIA_AUTH_PASSWORD}|g" "$_mihomo_dir/$_yaml_name"
        sed -i "s|<<HYSTERIA_OBFS_PASSWORD>>|${HYSTERIA_OBFS_PASSWORD}|g" "$_mihomo_dir/$_yaml_name"
    fi

    if [[ -n "$TROJAN_AUTH_PASSWORD" ]]; then
        sed -i "s|<<TROJAN_NAME>>|$(get_proxy_name | sed 's/[&/\]/\\&/g') Trojan|g" "$_mihomo_dir/$_yaml_name"
        sed -i "s|<<TROJAN_LISTEN_PORT>>|${TROJAN_LISTEN_PORT}|g" "$_mihomo_dir/$_yaml_name"
        sed -i "s|<<TROJAN_AUTH_PASSWORD>>|${TROJAN_AUTH_PASSWORD}|g" "$_mihomo_dir/$_yaml_name"
    fi
}

get_mihomo_subscription() {
    local _yaml_name
    local _mihomo_dir="/var/www/$SERVER_DOMAIN/public/mihomo/"

    _yaml_name=$(find "$_mihomo_dir" -type f -name "*.yaml" -exec basename {} \;)

    echo "https://$SERVER_DOMAIN/mihomo/$_yaml_name"
}

# NOTE: Functions for show prompt information
show_usage() {
    echo
    echo -e "            Trojan & Hysteria Server Installer Script"
    echo
    echo -e "                   Copyright (c) 2024 reagin"
    echo
    echo -e "Usage: "
    echo -e "   [ENVIRONMENT] $0  Command  [Option]"
    echo
    echo -e "Commands: "
    echo -e "    --help             Show help information"
    echo -e "    --remove           [ all / acme / cert / nginx / trojan / hysteria ]"
    echo -e "                       all:  Delete all contents (default option)"
    echo -e "                       acme: You can delete it at any time，but after delete"
    echo -e "                             acme, can't update the certificate automatically"
    echo -e "                       cert: If you are still using nginx, trojan, hysteria"
    echo -e "                             , then you'd better not delete CERT"
    echo -e "                       nginx: If you are still using trojan, hysteria, it's"
    echo -e "                             best not to delete nginx. It provides web"
    echo -e "                             services for the former"
    echo -e "                       trojan: You can delete it at any time"
    echo -e "                       hysteria: You can delete it at any time"
    echo -e "    --install          [ all / acme / cert / nginx / trojan / hysteria ]"
    echo -e "                       all:  Install all contents (default option)"
    echo -e "                       acme: You can install it at any time, and it is also the "
    echo -e "                             basic service of the rest"
    echo -e "                       cert: If you want to install cert, then acme will be"
    echo -e "                             automatically installed, and you can uninstall"
    echo -e "                             it yourself later"
    echo -e "                       nginx: When installing nginx, acme and cert will be"
    echo -e "                             automatically installed. You can uninstall acme"
    echo -e "                             later, but the normal operation of Nginx depends"
    echo -e "                             on cert"
    echo -e "                       trojan: Trojan's operation depends on nginx and cert."
    echo -e "                             At the same time, acme will be installed automatically."
    echo -e "                             If you need it, you can delete it later"
    echo -e "                       hysteria: Hysteria's operation depends on cert, and"
    echo -e "                             acme will be automatically installed"
    echo -e "    --reloadcmd        Update the reload command of acme.sh"
    echo -e "    --environment      Display available environment variables"
    echo -e "    --information      Display system && subscription information"
    echo -e "    --changepassword   Change the password of the current configuration file"
    echo
}

show_environment() {
    echo
    echo -e "            Trojan & Hysteria Server Installer Script"
    echo
    echo -e "                   Copyright (c) 2024 reagin"
    echo
    echo -e "Environment: "
    echo -e "    ACME_CERT_DIR                  (default: $ACME_CERT_DIR)"
    echo -e "    SERVER_DOMAIN                  (default: $SERVER_DOMAIN)"
    echo -e "    PERSONAL_EMAIL                 (default: $PERSONAL_EMAIL)"
    echo -e "    TROJAN_LISTEN_PORT             (default: $TROJAN_LISTEN_PORT)"
    echo -e "    TROJAN_AUTH_PASSWORD           (default: $TROJAN_AUTH_PASSWORD)"
    echo -e "    HYSTERIA_LISTEN_PORT           (default: $HYSTERIA_LISTEN_PORT)"
    echo -e "    HYSTERIA_HOPPING_RANGE         (default: $HYSTERIA_HOPPING_RANGE)"
    echo -e "    HYSTERIA_AUTH_PASSWORD         (default: $HYSTERIA_AUTH_PASSWORD)"
    echo -e "    HYSTERIA_OBFS_PASSWORD         (default: $HYSTERIA_OBFS_PASSWORD)"
    echo
}

show_information() {
    # shellcheck disable=SC2155
    local _server_ip="$(curl -s https://api.ip.sb/ip -A Mozilla)"

    echo
    echo -ne "Server IP:        " && mnote "$_server_ip"
    echo -ne "Server Domain:    " && mnote "$SERVER_DOMAIN"
    echo -ne "Personal Email:   " && mnote "$PERSONAL_EMAIL"

    if [[ -n "$TROJAN_AUTH_PASSWORD" ]]; then
        echo
        echo "Trojan: "
        echo
        echo -ne "    Listening Port:           " && mnote "$TROJAN_LISTEN_PORT"
        echo -ne "    Authenticate Password:    " && mnote "$TROJAN_AUTH_PASSWORD"
    fi

    if [[ -n "$HYSTERIA_AUTH_PASSWORD" ]]; then
        echo
        echo "Hysteria: "
        echo
        echo -ne "    Listening Port:           " && mnote "$HYSTERIA_LISTEN_PORT"
        echo -ne "    Port Hopping Range:       " && mnote "$HYSTERIA_HOPPING_RANGE"
        echo -ne "    Masquerade Password:      " && mnote "$HYSTERIA_OBFS_PASSWORD"
        echo -ne "    Authenticate Password:    " && mnote "$HYSTERIA_AUTH_PASSWORD"
    fi

    if has_command "nginx" && [[ -n "$TROJAN_AUTH_PASSWORD" || -n "$HYSTERIA_AUTH_PASSWORD" ]]; then

        generate_mihomo_subscription

        echo
        echo "Subscription: "
        echo
        echo -ne "    mihomo:   " && mnote "$(get_mihomo_subscription)"
    fi

    echo && return
}

change_password() {
    [[ -n "$TROJAN_AUTH_PASSWORD" ]] && TROJAN_AUTH_PASSWORD="$(generate_random_password)"
    [[ -n "$HYSTERIA_AUTH_PASSWORD" ]] && HYSTERIA_AUTH_PASSWORD="$(generate_random_password)"
    [[ -n "$HYSTERIA_OBFS_PASSWORD" ]] && HYSTERIA_OBFS_PASSWORD="$(generate_random_password)"

    mhead && mnote "Modifying the password ... " "true"

    if has_command "nginx" && [[ -n "$TROJAN_AUTH_PASSWORD" || -n "$HYSTERIA_AUTH_PASSWORD" ]]; then
        msuccess "done"
        show_information
    else
        merror "error"
        mhead && merror "Please make sure nginx && configuration file exists" && exit 6
    fi
}

parse_arguments() {
    # Create a temporary directory and save the downloaded file temporarily
    create_temporary_folder
    # Get the information of the current configuration file
    get_trojan_auth_password
    get_hysteria_auth_password
    get_hysteria_obfs_password

    while [[ "$#" -gt '0' ]]; do
        case "$1" in
        'help' | '--help')
            shift && [[ -z "$OPERATION" ]] && OPERATION="help"
            ;;
        'remove' | '--remove')
            shift && [[ -z "$OPERATION" ]] && OPERATION="remove_${1:-"all"}"
            [[ -n ${1:-} ]] && shift
            ;;
        'install' | '--install')
            shift && [[ -z "$OPERATION" ]] && OPERATION="install_${1:-"all"}"
            [[ -n ${1:-} ]] && shift
            ;;
        'reloadcmd' | '--reloadcmd')
            shift && [[ -z "$OPERATION" ]] && OPERATION="reloadcmd"
            [[ -n ${1:-} ]] && shift
            ;;
        'environment' | '--environment')
            shift && [[ -z "$OPERATION" ]] && OPERATION="environment"
            ;;
        'information' | '--information')
            shift && [[ -z "$OPERATION" ]] && OPERATION="information"
            ;;
        'changepassword' | '--changepassword')
            shift && [[ -z "$OPERATION" ]] && OPERATION="changepassword"
            ;;
        *)
            show_argument_error_and_exit "Unknown command: '$1'"
            ;;
        esac
    done

    # Default option
    OPERATION=${OPERATION:-"help"}
    # Global configuration certificate path
    PRIVATE_KEY_PATH="$ACME_CERT_DIR/$SERVER_DOMAIN/private.key"
    PUBLIC_PEM_PATH="$ACME_CERT_DIR/$SERVER_DOMAIN/public.pem"

    if [[ "$OPERATION" == "help" ]]; then
        show_usage && exit 0
    elif [[ "$OPERATION" == "reloadcmd" ]]; then
        update_reloadcmd && exit 0
    elif [[ "$OPERATION" == "environment" ]]; then
        show_environment && exit 0
    elif [[ "$OPERATION" == "information" ]]; then
        show_information && exit 0
    elif [[ "$OPERATION" == "changepassword" ]]; then
        change_password && exit 0
    fi
}

main() {
    parse_arguments "$@"

    # Check the system status
    check_permission
    check_operating_system
    check_dependent_software

    if has_prefix "$OPERATION" "remove_"; then
        OPERATION="${OPERATION#remove_}"
        case "$OPERATION" in
        "all")
            uninstall_acme
            uninstall_cert
            uninstall_nginx
            uninstall_trojan
            uninstall_hysteria
            ;;
        "acme")
            uninstall_acme
            ;;
        "cert")
            uninstall_cert
            uninstall_nginx
            uninstall_trojan
            uninstall_hysteria
            ;;
        "nginx")
            uninstall_nginx
            uninstall_trojan
            uninstall_hysteria
            ;;
        "trojan")
            uninstall_trojan
            ;;
        "hysteria")
            uninstall_hysteria
            ;;
        *)
            show_argument_error_and_exit "Unknown option: '$1'"
            ;;
        esac
        mnote ""
        msuccess "      Uninstallation Completed"
        mnote ""
        mnote "You may want to run the following steps: "
        mnote ""
        mnote "    * $0 --reloadcmd"
        mnote "    * systemctl restart nftables.service"
        mnote ""
    elif has_prefix "$OPERATION" "install_"; then
        OPERATION="${OPERATION#install_}"
        case "$OPERATION" in
        "all")
            install_acme
            install_cert
            install_nginx
            install_trojan
            install_hysteria
            ;;
        "acme")
            install_acme
            ;;
        "cert")
            install_acme
            install_cert
            ;;
        "nginx")
            install_acme
            install_cert
            install_nginx
            ;;
        "trojan")
            install_acme
            install_cert
            install_nginx
            install_trojan
            ;;
        "hysteria")
            install_acme
            install_cert
            install_nginx
            install_hysteria
            ;;
        *)
            show_argument_error_and_exit "Unknown option: '$1'"
            ;;
        esac
        mnote ""
        msuccess "      Installation Completed"
        show_information
        mnote "If necessary, please run following step: "
        mnote ""
        mnote "    * nft list ruleset"
        mnote "    * $0 --reloadcmd"
        mnote "    * systemctl restart nginx.service"
        mnote "    * systemctl restart nftables.service"
        mnote "    * systemctl restart trojan-server.service"
        mnote "    * systemctl restart hysteria-server.service"
    fi
}

# Start Script Here
main "$@"
