#!/usr/bin/env bash

#
#          Personal Initialize Script
#
#  Github: https://github.com/reagin/resources
#
#

#& If an error occurs, exit the script
set -o errexit
#& If any subcommand fails, the entire pipeline command fails
set -o pipefail
#& Causes trap to catch errors within functions
set -Eeuo pipefail

#! COMMAND REPLACEMENT & UTILITIES

install_content() {
    local _tmpfile
    local _install_flags="$1"
    local _content="$2"
    local _destination="$3"
    local _overwrite="$4"

    _tmpfile=$(mktemp)

    echo "$_content" >"$_tmpfile"
    echo -ne "Installing $_destination ... "

    if [[ -z "$_overwrite" && -e "$_destination" ]]; then
        echo "existed"
    elif install "$_install_flags" "$_tmpfile" "$_destination"; then
        echo "done"
    fi

    rm -rf "$_tmpfile"
}

generate_authorized_keys() {
    cat <<EOF
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDDCUfhnts8LB/QKd09EM9EjK983AvL9FRB39+AWwGmdN7tcHQaT5QOMpDSVV/uAGYCF+K4ErBt/gntVSLYw/T9q36oS41THr+4lGTKU+PhLdI/BFP93Sis3GjCpcKRvp8nEWTSkfuYvWZ35rXIiaPY4qlcsWKr6Id2g7Xr4RtcFxKOQTPbSaC3y3+9d9F1KBSl9NYqk578DrPPaqf+jS+Is/jfCNhbpeuuuBCBt7SFR/BcoRufzyM5+MTiJ6QOEMGGv3fQtGt7wrYcMajkaBdO3mELOAxA+MSxWs3pIU7HP1JqzVtR3DzGQUsnUbsoP6FSPUPPp/tZwkSCNs1lkzcQFhKlJEY4ZiePGZA22OJUMRc7MhiR4cM0pXA/NKPbO0jesUJ5SqstcLEJnTv7+Uv7OICXdRXc0l9sNv+vC/C65Rr4W6mkv+WVc+tDRw79Zmk635wGhuPRTxsUDRY/GZ4w+5gNnuMZQzBQe/LoNwVJ4Pa/hlRSF6WEDU+NoEtd7IJdp2fCSW0XOp1W0ObmA2MNfcRNQbaHUdnQHFFE89+BI3ElxAoz3Ycu9r8CvkUaxb/KSKEtxSkyYDJD+29H0pWG3ws0Z7VFzOfOo0fSjOOduOAole2fOwXyF0wVF2AtjG6xjT+2pV9tCK0R9wt022VPiSpT80nbjuUKqDpzLCwmVw== reagin@163.com
EOF
}

generate_alias_config() {
    cat <<EOF
alias cls='clear'
EOF
}

generate_vim_config() {
    cat <<EOF
" 打开语法高亮
syntax on
" 显示行号
set number
" C语言自动缩进
set cindent
" 自动缩进
set autoindent
" 智能缩进
set smartindent
" 智能制表符
set smarttab
" 将制表符转换为空格
set expandtab
" 启用256色
set t_Co=256
" 使用 utf-8 编码
set encoding=utf-8
" 制表符宽度为4
set tabstop=4
" 普通缩进宽度为4
set shiftwidth=4
" 按下Tab键时插入4个空格
set softtabstop=4
" 禁止备份文件
set nobackup
" 禁止交换文件
set noswapfile
" 禁止将制表符转换为空格
set noexpandtab
" 关闭兼容模式
set nocompatible
EOF
}

# 更新软件源和所有的软件
apt update && apt -y upgrade

# 简单个性化设置所有的用户目录
for user_dir in /root /home/*; do
    if [ -d "$user_dir" ]; then
        _user_name=$(basename "$user_dir")

        # 生成文件
        install_content -Dm600 "$(generate_authorized_keys)" "$user_dir/.ssh/authorized_keys" "1"
        install_content -Dm644 "$(generate_alias_config)" "$user_dir/.bash_aliases" "1"
        install_content -Dm644 "$(generate_vim_config)" "$user_dir/.vimrc" "1"
        install_content -Dm644 "" "$user_dir/.hushlogin" "1"

        # 更改文件的用户组
        chown "$_user_name":"$_user_name" "$user_dir/.ssh/authorized_keys"
        chown "$_user_name":"$_user_name" "$user_dir/.bash_aliases"
        chown "$_user_name":"$_user_name" "$user_dir/.vimrc"
        chown "$_user_name":"$_user_name" "$user_dir/.hushlogin"

        # 修改文件内容
        sed -i 's/^.*force_color_prompt=yes$/force_color_prompt=yes/' "$user_dir/.bashrc"
        sed -i '/# some more ls aliases/{n;N;N;d;}' "$user_dir/.bashrc"
        sed -i '/# some more ls aliases/a alias l='\''ls -CF'\''' "$user_dir/.bashrc"
        sed -i '/# some more ls aliases/a alias la='\''ls -A'\''' "$user_dir/.bashrc"
        sed -i '/# some more ls aliases/a alias ll='\''ls -AlF'\''' "$user_dir/.bashrc"

        sed -i "/^if \[ \"\$color_prompt\" = yes \]; then/{n;d}" "$user_dir/.bashrc"
        if [ "$_user_name" = "root" ]; then
            sed -i "/^if \[ \"\$color_prompt\" = yes \]; then/a \    PS1=\'\${debian_chroot:+(\$debian_chroot)}\\\\[\\\\033[01;31m\\\\]\\\\u@\\\\h\\\\[\\\\033[00m\\\\]:\\\\[\\\\033[01;35m\\\\]\\\\w \\\\$\\\\[\\\\033[00m\\\\] \'" "$user_dir/.bashrc"
        else
            sed -i "/^if \[ \"\$color_prompt\" = yes \]; then/a \    PS1=\'\${debian_chroot:+(\$debian_chroot)}\\\\[\\\\033[01;32m\\\\]\\\\u@\\\\h\\\\[\\\\033[00m\\\\]:\\\\[\\\\033[01;34m\\\\]\\\\w \\\\$\\\\[\\\\033[00m\\\\] \'" "$user_dir/.bashrc"
        fi

        # 删除多余的文件
        for path in \
            "$user_dir/.cloud-locale-test.skip" \
            "$user_dir/.bash_history" \
            "$user_dir/.wget-hsts" \
            "$user_dir/.vimrc"; do
            if [[ -e "$path" ]]; then
                rm -rf "$path"
            fi
        done
    fi
done

# 修改ssh_config
sed -i 's/^.*PermitRootLogin.*$/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sed -i 's/^.*PasswordAuthentication.*$/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^.*PermitEmptyPasswords.*$/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sed -i 's/^.*ClientAliveInterval.*$/ClientAliveInterval 60/' /etc/ssh/sshd_config
sed -i 's/^.*ClientAliveCountMax.*$/ClientAliveCountMax 3/' /etc/ssh/sshd_config

# 自启动部分服务项
systemctl enable ssh.service

# 删除根目录多余的文件夹
rm -rf /*.usr-is-merged
rm -rf /lost+found

history -c && reboot
