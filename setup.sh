#!/bin/bash
apt update -y
apt upgrade -y
apt install grep -y
apt install curl -y
apt install git -y

spinner()
{
    #Loading spinner
    local pid=$!
    local delay=0.75
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}
permission () {
    echo -e "$text┌─────────────────────────────────────────────────┐${NC}"
    echo -e "$text│${NC} ${bg}                 • License Key  •              ${NC} $text│$NC"
    echo -e "$text└─────────────────────────────────────────────────┘${NC}"
    echo -e "$text┌─────────────────────────────────────────────────┐${NC}"
    read -s -rp "  License Key : " -e pp
    echo ""
    MYIP=$(curl -s https://checkip.amazonaws.com/);
    echo ""
    echo -e "${LIGHT}Checking You License${NC}"
    sleep 2
    clear
    MYIP=$(curl -sS ipv4.icanhazip.com)
    IZIN=$( curl -s https://createssh.net/pass/licensey | grep $pp )
    if [ "$pp" = "$IZIN" ]; then
    echo ""
    echo "Thanks You For Use Script Auto Install Myteam"
    echo "Do Not Forget Support Us Jrtunnel"
    echo "See You"
    echo ""
    echo -e "${green}License OK Installer${NC}"
    echo ""
    sleep 2
    clear
    echo ""
    else
    echo ""
    echo -e "License not Valid Installer Script!"
    echo -e "Only For Team Jrtunnel"
    echo ""
    sleep 2
    clear
    permission
    fi
}
cd /root
#System version number
if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
fi
if [ "$(systemd-detect-virt)" == "openvz" ]; then
		echo "OpenVZ is not supported"
		exit 1
fi
# ==========================================
# Color
RED='\033[0;31m'
NC='\033[0m'
green='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
green='\033[0;36m'
LIGHT='\033[0;37m'
red='\e[1;31m'
green='\E[40;1;42m'
text='\033[0;34m'
bg='\E[40;1;44m'
yell='\E[40;1;43m'
NC='\e[0m'
# =========================================
# Getting
clear
echo -e "[ ${text}NOTES${NC} ] Before we go.. "
sleep 1
echo -e "[ ${text}NOTES${NC} ] I need check your headers first.."
sleep 2
echo -e "[ ${green}INFO${NC} ] Checking headers"
  sleep 1
  echo ""
  echo -e "[ ${yell}WARNING${NC} ] Try to install ...."
  echo -e "[ ${text}NOTES${NC} ] If error you need.. to do this"
  echo -e "[ ${text}NOTES${NC} ] 1. apt update -y"
  echo -e "[ ${text}NOTES${NC} ] 2. apt upgrade -y"
  echo -e "[ ${text}NOTES${NC} ] 3. apt dist-upgrade -y"
  echo -e "[ ${text}NOTES${NC} ] 4. reboot"
  echo -e "[ ${text}NOTES${NC} ] After rebooting"
  sleep 1
  echo -e "[ ${text}NOTES${NC} ] Then run this script again"
  echo -e "[ ${text}NOTES${NC} ] Notes, Script By : CreateSSH Network"
  echo -e "[ ${text}NOTES${NC} ] if you understand then tap enter now.."
  read
  echo ""
  echo -e "[ ${green}INFO${NC} ] Oke installed"
  echo ""
  sleep 1
  clear
RED='\033[0;31m'
NC='\033[0m'
green='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
green='\033[0;36m'
LIGHT='\033[0;37m'
red='\e[1;31m'
green='\E[40;1;42m'
text='\033[0;34m'
bg='\E[40;1;44m'
NC='\e[0m'

permission

################ INSTALLER #################
domain()
{
MYIP=$(wget -qO- ipinfo.io/ip);
echo -e "${green}XRay Multi Port Jrtunnel${NC}"
sleep 1
IZIN=$(wget -qO- ipinfo.io/ip);
clear
echo -e "${green}Setting Up Domain${NC}"
sleep 1
apt install jq curl -y
DOMAIN=xraybest.ninja
sub=$(</dev/urandom tr -dc a-z0-9 | head -c4)
SUB_DOMAIN=${sub}.xraybest.ninja
CF_ID=vstunnel@gmail.com
CF_KEY=bf2f943aba9cefaf4cc246ab198519ab15e93
set -euo pipefail
IP=$(wget -qO- icanhazip.com)
echo "Updating DNS for ${SUB_DOMAIN}..."
ZONE=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones?name=${DOMAIN}&status=active" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" | jq -r .result[0].id)

RECORD=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records?name=${SUB_DOMAIN}" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" | jq -r .result[0].id)

if [[ "${#RECORD}" -le 10 ]]; then
     RECORD=$(curl -sLX POST "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" \
     --data '{"type":"A","name":"'${SUB_DOMAIN}'","content":"'${IP}'","ttl":120,"proxied":false}' | jq -r .result.id)
fi

RESULT=$(curl -sLX PUT "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records/${RECORD}" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" \
     --data '{"type":"A","name":"'${SUB_DOMAIN}'","content":"'${IP}'","ttl":120,"proxied":false}')
echo $SUB_DOMAIN > /root/domain
mkdir -p /etc/xray
echo $SUB_DOMAIN > /etc/xray/domain
echo -e "${green}Host : $SUB_DOMAIN..${NC}"
echo 'SSH SlowDNS CreateSSH.net' > /etc/issue.net
echo -e "${green}OK..${NC}"
sleep 1
mkdir /var/lib/premium-script;
echo "IP=$SUB_DOMAIN" >> /var/lib/premium-script/ipvps.conf
echo "";
#Install SSH
}
echo -ne "${green}Installer Tools!...${NC}"
domain >/dev/null 2>&1 &
spinner
echo ""
clear
echo -e "${green}Installer Domain Successfully!${NC}"
cd
clear
#install tools/alat
echo -e "${green}Installer Tools Dan ALat${NC}";
sleep 1
wget -q --show-progress https://raw.githubusercontent.com/khairunisya/xrayweb/main/install-tools.sh && chmod +x install-tools.sh && ./install-tools.sh
#
#Instal Xray
echo -e "${green}Installer Xray Server${NC}";
sleep 1
wget -q --show-progress https://raw.githubusercontent.com/khairunisya/xrayweb/main/install-xray.sh && chmod +x install-xray.sh && ./install-xray.sh
#install xmenu
echo -e "${green}Installer Update${NC}";
sleep 1
wget -q --show-progress https://raw.githubusercontent.com/khairunisya/xrayweb/main/menu/update.sh && chmod +x update.sh && ./update.sh
#
#install bbr
echo -e "${green}Installer BBR Servers${NC}";
sleep 1
wget -q --show-progress https://raw.githubusercontent.com/khairunisya/xrayweb/main/bbr.sh && chmod +x bbr.sh && ./bbr.sh
#install Wireguard
echo -e "${green}Installer Wireguard Servers${NC}";
sleep 1
wget -q --show-progress https://raw.githubusercontent.com/khairunisya/xrayweb/main/wg.sh && chmod +x wg.sh && ./wg.sh
#SELESAI
echo -e "${green}Installer SlowDNS Servers${NC}";
sleep 1
#wget -q --show-progress https://github.com/khairunisya/xrayweb/raw/main/slowdns/install-sldns.sh && chmod +x install-sldns.sh && ./install-sldns.sh
#SELESAI
echo -e "${green}Installer All Services Successfully!${NC}";
sleep 1
echo " "
echo "Instalasi Selesai!"
echo "============================================================================" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "----------------------------------------------------------------------------" | tee -a log-install.txt
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"  | tee -a log-install.txt
echo -e "    Xray Multi Port 443 Jrtunnel"  | tee -a log-install.txt
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   >>> Service & Port"  | tee -a log-install.txt
echo "   - Nginx                           : 89"  | tee -a log-install.txt
echo "   - XRAY Trojan WebSocket TLS       : 443"  | tee -a log-install.txt
echo "   - XRAY Trojan gRPC                : 443"  | tee -a log-install.txt
echo "   - XRAY Trojan WebSocket HTTP      : 80"  | tee -a log-install.txt
echo "   - XRAY Vmess WebSocket TLS        : 443"  | tee -a log-install.txt
echo "   - XRAY Vmess WebSocket HTTP       : 80"  | tee -a log-install.txt
echo "   - XRAY Vmess gRPC                 : 443"  | tee -a log-install.txt
echo "   - XRAY Vless WebSocket TLS        : 443"  | tee -a log-install.txt
echo "   - XRAY Vless gRPC                 : 443"  | tee -a log-install.txt
echo "   - XRAY Vless WebSocket HTTP       : 80"  | tee -a log-install.txt
echo "   - XRAY Shadowsocks WebSocket TLS  : 443"  | tee -a log-install.txt
echo "   - XRAY Shadowsocks gRPC           : 443"  | tee -a log-install.txt
echo "   - XRAY Shadowsocks WebSocket HTTP : 80"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   >>> Server Information & Other Features"  | tee -a log-install.txt
echo "   - Timezone                : Asia/Jakarta (GMT +7)"  | tee -a log-install.txt
echo "   - Fail2Ban                : [ON]"  | tee -a log-install.txt
echo "   - Dflate                  : [ON]"  | tee -a log-install.txt
echo "   - IPtables                : [ON]"  | tee -a log-install.txt
echo "   - Auto-Reboot             : [ON]"  | tee -a log-install.txt
echo "   - Bot Servers VPS         : [ON]"  | tee -a log-install.txt
echo "   - IPv6                    : [OFF]"  | tee -a log-install.txt
echo "   - Autoreboot On 05.00 GMT +7" | tee -a log-install.txt
echo "   - Autobackup Data" | tee -a log-install.txt
echo "   - Restore Data" | tee -a log-install.txt
echo "   - Auto Delete Expired Account" | tee -a log-install.txt
echo "   - Full Orders For Various Services" | tee -a log-install.txt
echo "   - White Label" | tee -a log-install.txt
echo "   - Installation Log --> /root/log-install.txt"  | tee -a log-install.txt
echo " Reboot 10 Sec"
sleep 5
echo -e "${green}Thanks You For Use AutoScript Jrtunnel!${NC}";
sleep 1
cd
rm -rf update
rm -rf update.sh
rm -rf setup.sh
rm -rf install-xray.sh
rm -rf install-tools.sh
rm -rf wg.sh
