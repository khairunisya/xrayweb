# XRay-Install-v4

<li>Tahap 1</li>
<pre><code>apt update && apt upgrade -y --fix-missing && update-grub && sleep 2 && reboot</code></pre>

<li>Tahap 2</li>
<pre><code>rm -f setup.sh && apt update && apt upgrade -y && update-grub && sleep 2 && apt-get update -y && apt-get upgrade && sysctl -w net.ipv6.conf.all.disable_ipv6=1 && sysctl -w net.ipv6.conf.default.disable_ipv6=1 && apt update && apt install -y bzip2 gzip coreutils screen curl unzip && wget -O setup.sh https://raw.githubusercontent.com/khairunisya/xrayweb/main/setup.sh && chmod +x setup.sh && sed -i -e 's/\r$//' setup.sh && screen -S setup ./setup.sh</code></pre>

AutoScript Installer By Jrtunnel
