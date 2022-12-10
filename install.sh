#!/bin/bash
if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
fi
if [ "$(systemd-detect-virt)" == "openvz" ]; then
		echo "OpenVZ is not supported"
		exit 1
fi
apt update -y
apt upgrade -y
update-grub -y
apt install grep -y
apt install curl -y
apt install vnstat -y
apt install jq curl -y
# ==========================================
# Color
RED='\033[0;31m'
NC='\033[0m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
LIGHT='\033[0;37m'
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'
# =========================================
# Getting
MYIP=$(wget -qO- ipinfo.io/ip);
echo -e "${green}XRay Multi Port By TurboSSH ${SUB_DOMAIN}...${NC}"
IZIN=$(wget -qO- ipinfo.io/ip);
clear
mkdir /var/lib/premium-script;
echo "IP=" >> /var/lib/premium-script/ipvps.conf

echo "";
echo -e "${green}Setting Up Domain${NC}"
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
echo 'Connected to Server XRay Program By TurboSSH...' > /etc/issue.net
echo -e "${green}OK..${NC}"
sleep 1
#Install SSH
echo -e "${green}Installing XRay Program....${NC}";
sleep 2
#Install XRay

cd
#install tools/alat
wget -q --show-progress https://raw.githubusercontent.com/Gugun09/xray-install-v2/main/install-tools.sh && chmod +x install-tools.sh && ./install-tools.sh
#
#Instal Xray
wget -q --show-progress https://raw.githubusercontent.com/Gugun09/xray-install-v2/main/install-xray.sh && chmod +x install-xray.sh && ./install-xray.sh
#install xmenu
wget -q --show-progress https://raw.githubusercontent.com/fisabiliyusri/XRAY-MANTAP/main/menu/updatedll.sh && chmod +x updatedll.sh && ./updatedll.sh
#
#install bbr
wget -q --show-progress https://raw.githubusercontent.com/fisabiliyusri/Mantap/main/ssh/bbr.sh && chmod +x bbr.sh && screen -S bbr ./bbr.sh
#SELESAI
echo " "
echo "Instalasi Selesai!"echo " "
echo "============================================================================" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "----------------------------------------------------------------------------" | tee -a log-install.txt
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"  | tee -a log-install.txt
echo -e "    Xray Multi Port 443 By TurboSSH"  | tee -a log-install.txt
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
echo "   - IPv6                    : [OFF]"  | tee -a log-install.txt
echo "   - Autoreboot On 05.00 GMT +7" | tee -a log-install.txt
echo "   - Autobackup Data" | tee -a log-install.txt
echo "   - Restore Data" | tee -a log-install.txt
echo "   - Auto Delete Expired Account" | tee -a log-install.txt
echo "   - Full Orders For Various Services" | tee -a log-install.txt
echo "   - White Label" | tee -a log-install.txt
echo "   - Installation Log --> /root/log-install.txt"  | tee -a log-install.txt
echo " Reboot 15 Sec"
sleep 15
cd
rm -rf updatedll
rm -rf updatedll.sh
rm -rf setup.sh
rm -rf install-xray.sh
rm -rf install-tools.sh

