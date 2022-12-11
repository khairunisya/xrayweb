#!/bin/bash

# Secure WireGuard server installer
# Source By Jrtunnel

RED='\033[0;31m'
GREEN='\e[0;32m'
ORANGE='\033[0;33m'
NC='\033[0m'

    # checkVirt
    echo -e "$GREEN[INFO]$NC Check Virt!"
    sleep 1
	if [ "$(systemd-detect-virt)" == "openvz" ]; then
		echo "OpenVZ is not supported"
		exit 1
	fi

	if [ "$(systemd-detect-virt)" == "lxc" ]; then
		echo "LXC is not supported (yet)."
		echo "WireGuard can technically run in an LXC container,"
		echo "but the kernel module has to be installed on the host,"
		echo "the container has to be run with some specific parameters"
		echo "and only the tools need to be installed in the container."
		exit 1
	fi
    echo -e "$GREEN[INFO]$NC Check Version OS!"
    sleep 1
	# Check OS version
	if [[ -e /etc/debian_version ]]; then
		source /etc/os-release
		OS="${ID}" # debian or ubuntu
		if [[ ${ID} == "debian" || ${ID} == "raspbian" ]]; then
			if [[ ${VERSION_ID} -lt 10 ]]; then
				echo "Your version of Debian (${VERSION_ID}) is not supported. Please use Debian 10 Buster or later"
				exit 1
			fi
			OS=debian # overwrite if raspbian
		fi
	elif [[ -e /etc/almalinux-release ]]; then
		source /etc/os-release
		OS=almalinux
	elif [[ -e /etc/fedora-release ]]; then
		source /etc/os-release
		OS="${ID}"
	elif [[ -e /etc/centos-release ]]; then
		source /etc/os-release
		OS=centos
	elif [[ -e /etc/oracle-release ]]; then
		source /etc/os-release
		OS=oracle
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	else
		echo "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS, AlmaLinux, Oracle or Arch Linux system"
		exit 1
	fi

    echo -e "$GREEN[INFO]$NC Welcome to the WireGuard installer!"
    sleep 1
	echo "$GREEN[INFO]$NC Auto ScriptInstaller By: https://www.jrtunnel.com"
	echo ""
	echo "$GREEN[INFO]$NC I need to ask you a few questions before starting the setup."
	echo "$GREEN[INFO]$NC You can leave the default options and just press enter if you are ok with them."
	echo ""
	echo ""
	echo "$GREEN[INFO]$NC Okay, that was all I needed. We are ready to setup your WireGuard server now."
	echo "$GREEN[INFO]$NC You will be able to generate a client at the end of the installation."


    # Install WireGuard tools and module
    echo -e "$GREEN[INFO]$NC Install WireGuard Tools and Module!"
    sleep 1
	if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' && ${VERSION_ID} -gt 10 ]]; then
		apt-get update
		apt-get install -y wireguard iptables resolvconf qrencode
	elif [[ ${OS} == 'debian' ]]; then
		if ! grep -rqs "^deb .* buster-backports" /etc/apt/; then
			echo "deb http://deb.debian.org/debian buster-backports main" >/etc/apt/sources.list.d/backports.list
			apt-get update
		fi
		apt update
		apt-get install -y iptables resolvconf qrencode
		apt-get install -y -t buster-backports wireguard
	elif [[ ${OS} == 'fedora' ]]; then
		if [[ ${VERSION_ID} -lt 32 ]]; then
			dnf install -y dnf-plugins-core
			dnf copr enable -y jdoss/wireguard
			dnf install -y wireguard-dkms
		fi
		dnf install -y wireguard-tools iptables qrencode
	elif [[ ${OS} == 'almalinux' ]]; then
		dnf -y install epel-release elrepo-release
		dnf -y install wireguard-tools iptables qrencode
		if [[ ${VERSION_ID} == 8* ]]; then
			dnf -y install kmod-wireguard
		fi
	elif [[ ${OS} == 'centos' ]]; then
		yum -y install epel-release elrepo-release
		if [[ ${VERSION_ID} -eq 7 ]]; then
			yum -y install yum-plugin-elrepo
		fi
		yum -y install kmod-wireguard wireguard-tools iptables qrencode
	elif [[ ${OS} == 'oracle' ]]; then
		dnf install -y oraclelinux-developer-release-el8
		dnf config-manager --disable -y ol8_developer
		dnf config-manager --enable -y ol8_developer_UEKR6
		dnf config-manager --save -y --setopt=ol8_developer_UEKR6.includepkgs='wireguard-tools*'
		dnf install -y wireguard-tools qrencode iptables
	elif [[ ${OS} == 'arch' ]]; then
		pacman -S --needed --noconfirm wireguard-tools qrencode
	fi

	# Make sure the directory exists (this does not seem the be the case on fedora)
	mkdir /etc/wireguard >/dev/null 2>&1

	chmod 600 -R /etc/wireguard/

    SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
    SERVER_PUB_NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    SERVER_WG_NIC=wg0
    SERVER_WG_IPV4=10.66.66.1
    SERVER_WG_IPV6=fd42:42:42::1
    SERVER_PORT=51820
	SERVER_PRIV_KEY=$(wg genkey)
	SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)
    CLIENT_DNS_1=1.1.1.1
    CLIENT_DNS_2=1.0.0.1


	# Save WireGuard settings
	echo "SERVER_PUB_IP=${SERVER_PUB_IP}
    SERVER_PUB_NIC=${SERVER_PUB_NIC}
    SERVER_WG_NIC=${SERVER_WG_NIC}
    SERVER_WG_IPV4=${SERVER_WG_IPV4}
    SERVER_WG_IPV6=${SERVER_WG_IPV6}
    SERVER_PORT=${SERVER_PORT}
    SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
    SERVER_PUB_KEY=${SERVER_PUB_KEY}
    CLIENT_DNS_1=${CLIENT_DNS_1}
    CLIENT_DNS_2=${CLIENT_DNS_2}" >/etc/wireguard/params

	# Add server interface
	echo "[Interface]
Address = ${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}" >"/etc/wireguard/${SERVER_WG_NIC}.conf"

	if pgrep firewalld; then
		FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
		FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/:0/')
		echo "PostUp = firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	else
		echo "PostUp = iptables -A FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT; iptables -A FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE; ip6tables -A FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT; iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE; ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	fi

	# Enable routing on the server
    echo -e "$GREEN[INFO]$NC Enable routing on the server!"
    sleep 1
	echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" >/etc/sysctl.d/wg.conf

	sysctl --system

	systemctl start "wg-quick@${SERVER_WG_NIC}"
	systemctl enable "wg-quick@${SERVER_WG_NIC}"

	echo "If you want to add more clients, you simply need to run this script another time!"

	# Check if WireGuard is running
	systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
	WG_RUNNING=$?

	# WireGuard might not work if we updated the kernel. Tell the user to reboot
    echo -e "$GREEN[INFO]$NC WireGuard might not work if we updated the kernel. Tell the user to reboot!"
    sleep 1
	if [[ ${WG_RUNNING} -ne 0 ]]; then
		echo -e "\n${RED}WARNING: WireGuard does not seem to be running.${NC}"
		echo -e "${ORANGE}You can check if WireGuard is running with: systemctl status wg-quick@${SERVER_WG_NIC}${NC}"
		echo -e "${ORANGE}If you get something like \"Cannot find device ${SERVER_WG_NIC}\", please reboot!${NC}"
	fi

    # Tambahan
    cd /usr/bin
    wget -q --show-progress -O addwg "https://raw.githubusercontent.com/khairunisya/ssh/main/wireguard/addwg.sh"
    wget -q --show-progress -O delwg "https://raw.githubusercontent.com/khairunisya/ssh/main/wireguard/delwg.sh"
    wget -q --show-progress -O xpwgr "https://raw.githubusercontent.com/khairunisya/ssh/main/wireguard/xpwg.sh"
    chmod +x addwg
    chmod +x delwg
    chmod +x xpwgr
    cd
    echo "0 0 * * * root xpwgr" >> /etc/crontab

    echo -e "$GREEN[INFO]$NC Installer Succesfully By Jrtunnel!"
    sleep 1
    rm -f /root/wg.sh