# XRay-Install-v2

<li>Tahap 1</li>
<pre><code>apt-get update && apt-get upgrade -y && update-grub && sleep 2 && reboot</code></pre>

<li>Tahap 2</li>
<pre><code>rm -f setup.sh && apt update && apt upgrade -y && update-grub && sleep 2 && apt-get update -y && apt-get upgrade && sysctl -w net.ipv6.conf.all.disable_ipv6=1 && sysctl -w net.ipv6.conf.default.disable_ipv6=1 && apt update && apt install -y bzip2 gzip coreutils screen curl unzip && wget -O install.sh https://raw.githubusercontent.com/khairunisya/xrayweb/main/install.sh && chmod +x install.sh && sed -i -e 's/\r$//' install.sh && screen -S install ./install.sh</code></pre>

AutoScript Installer By Jrtunnel
