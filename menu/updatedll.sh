#!/bin/bash
# ==========================================
cd
rm -r updatedll
wget -O updatedll "https://raw.githubusercontent.com/khairunisya/xrayweb/main/menu/updatedll.sh"
rm -rf updatedll

# hapus
cd /usr/bin
rm -rf xmenu
rm -rf updatedll
rm -r updatedll
# download
#
cd /usr/bin
wget -O --show-progress xmenu "https://raw.githubusercontent.com/khairunisya/xrayweb/main/menu/xmenu.sh"
wget -O --show-progress add-akun "https://raw.githubusercontent.com/khairunisya/xrayweb/main/menu/add-akun.sh"
wget -O --show-progress updatedll "https://raw.githubusercontent.com/khairunisya/xrayweb/main/menu/updatedll.sh"
wget -O --show-progress add-akun "https://raw.githubusercontent.com/khairunisya/xrayweb/main/menu/add-akun.sh"
wget -O --show-progress delete-akun "https://raw.githubusercontent.com/khairunisya/xrayweb/main/menu/delete-akun.sh"
wget -O --show-progress certv2ray "https://raw.githubusercontent.com/khairunisya/Mantap/main/xray/certv2ray.sh"
wget -O --show-progress restart-xray "https://raw.githubusercontent.com/khairunisya/xrayweb/main/menu/restart-xray.sh"
wget -O --show-progress xmenu "https://raw.githubusercontent.com/khairunisya/xrayweb/main/menu/xmenu.sh"
wget -O --show-progress auto-pointing "https://raw.githubusercontent.com/khairunisya/xrayweb/main/menu/auto-pointing.sh"
wget -O --show-progress cek-port "https://raw.githubusercontent.com/khairunisya/xrayweb/main/menu/cek-port.sh"
wget -O --show-progress xmenu "https://raw.githubusercontent.com/khairunisya/xrayweb/main/menu/xmenu.sh"

#
chmod +x /usr/bin/updatedll
chmod +x /usr/bin/xmenu
chmod +x xmenu
chmod +x add-akun
chmod +x delete-akun
chmod +x updatedll
chmod +x add-akun
chmod +x certv2ray
chmod +x restart-xray
chmod +x auto-pointing
chmod +x cek-port

cd