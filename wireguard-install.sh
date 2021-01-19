#!/bin/bash
#
# https://github.com/Nyr/wireguard-install
#
# Copyright (c) 2020 Nyr. Released under the MIT License.

# Define 3 roles with 3 subnet to isolate
devops_subnet="10.7.0"
backend_subnet="10.7.1"
data_subnet="10.7.2"
dns="10.7.0.1"

firewall="iptables"

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
    echo 'This installer needs to be run with "bash", not "sh".'
    exit
fi

# Discard stdin. Needed when running from an one-liner which includes a newline
read -N 999999 -t 0.001

# Detect OpenVZ 6
if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
    echo "The system is running an old kernel, which is incompatible with this installer."
    exit
fi

# Detect OS
# $os_version variables aren't always in use, but are kept here for convenience
if grep -qs "ubuntu" /etc/os-release; then
    os="ubuntu"
    os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
    elif [[ -e /etc/debian_version ]]; then
    os="debian"
    os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
    elif [[ -e /etc/centos-release ]]; then
    os="centos"
    os_version=$(grep -oE '[0-9]+' /etc/centos-release | head -1)
    elif [[ -e /etc/fedora-release ]]; then
    os="fedora"
    os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
else
    echo "This installer seems to be running on an unsupported distribution.
    Supported distributions are Ubuntu, Debian, CentOS, and Fedora."
    exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
    echo "Ubuntu 18.04 or higher is required to use this installer.
    This version of Ubuntu is too old and unsupported."
    exit
fi

if [[ "$os" == "debian" && "$os_version" -lt 10 ]]; then
    echo "Debian 10 or higher is required to use this installer.
    This version of Debian is too old and unsupported."
    exit
fi

if [[ "$os" == "centos" && "$os_version" -lt 7 ]]; then
    echo "CentOS 7 or higher is required to use this installer.
    This version of CentOS is too old and unsupported."
    exit
fi

# Detect environments where $PATH does not include the sbin directories
if ! grep -q sbin <<< "$PATH"; then
	echo '$PATH does not include sbin. Try using "su -" instead of "su".'
	exit
fi

systemd-detect-virt -cq
is_container="$?"

if [[ "$os" == "fedora" && "$os_version" -eq 31 && $(uname -r | cut -d "." -f 2) -lt 6 && ! "$is_container" -eq 0 ]]; then
	echo 'Fedora 31 is supported, but the kernel is outdated.
Upgrade the kernel using "dnf upgrade kernel" and restart.'
	exit
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "This installer needs to be run with superuser privileges."
	exit
fi

if [[ "$is_container" -eq 0 ]]; then
	if [ "$(uname -m)" != "x86_64" ]; then
		echo "In containerized systems, this installer supports only the x86_64 architecture.
The system runs on $(uname -m) and is unsupported."
		exit
	fi
	# TUN device is required to use BoringTun if running inside a container
	if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
		echo "The system does not have the TUN device available.
TUN needs to be enabled before running this installer."
		exit
	fi
fi

new_client_setup () {
	# Select role for client first
	echo "Select a role for the client:"
	echo "   1) DevOps"
	echo "   2) Backend"
	echo "   3) Data Engineer/Scientist"
	read -p "Client role [1]: " client_role
	until [[ -z "$client_role" || "$client_role" =~ ^[1-3]$ ]]; do
		echo "$client_role: invalid selection."
		read -p "Client role [1]: " client_role
	done

	case "$client_role" in
		1|"")
			role_ip=$devops_subnet
		;;
		2)
			role_ip=$backend_subnet
		;;
		3)
			role_ip=$data_subnet
		;;
	esac
	# Given a list of the assigned internal IPv4 addresses, obtain the lowest still
	# available octet. Important to start looking at 2, because 1 is our gateway.
	octet=2
	while grep AllowedIPs /etc/wireguard/wg0.conf | grep $role_ip |cut -d "." -f 4 | cut -d "/" -f 1 | grep -q "$octet"; do
		(( octet++ ))
	done
	# Don't break the WireGuard configuration in case the address space is full
	if [[ "$octet" -eq 255 ]]; then
		echo "253 clients are already configured. The WireGuard internal subnet is full!"
		exit
	fi
	key=$(wg genkey)
	psk=$(wg genpsk)
	# Configure client in the server
	cat << EOF >> /etc/wireguard/wg0.conf
# BEGIN_PEER $client
[Peer]
PublicKey = $(wg pubkey <<< $key)
PresharedKey = $psk
AllowedIPs = $role_ip.$octet/32$(grep -q 'fddd:2c4:2c4:2c4::1' /etc/wireguard/wg0.conf && echo ", fddd:2c4:2c4:2c4::$octet/128")
# END_PEER $client
EOF
	# Create client configuration
	cat << EOF > "$PWD/client/$client".conf
[Interface]
Address = $role_ip.$octet/24$(grep -q 'fddd:2c4:2c4:2c4::1' /etc/wireguard/wg0.conf && echo ", fddd:2c4:2c4:2c4::$octet/64")
DNS = $dns
PrivateKey = $key

[Peer]
PublicKey = $(grep PrivateKey /etc/wireguard/wg0.conf | cut -d " " -f 3 | wg pubkey)
PresharedKey = $psk
AllowedIPs = 10.0.0.0/8, 172.177.1.0/24
Endpoint = $(grep '^# ENDPOINT' /etc/wireguard/wg0.conf | cut -d " " -f 3):$(grep ListenPort /etc/wireguard/wg0.conf | cut -d " " -f 3)
PersistentKeepalive = 25
EOF
}

if [[ ! -e /etc/wireguard/wg0.conf ]]; then
	clear
	echo 'Welcome to this WireGuard road warrior installer!'
	# If system has a single IPv4, it is selected automatically. Else, ask the user
	if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
		echo
		echo "Which IPv4 address should be used?"
		ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
		read -p "IPv4 address [1]: " ip_number
		until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
			echo "$ip_number: invalid selection."
			read -p "IPv4 address [1]: " ip_number
		done
		[[ -z "$ip_number" ]] && ip_number="1"
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
	fi
	# If $ip is a private IP address, the server must be behind NAT
	if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo
		echo "This server is behind NAT. What is the public IPv4 address or hostname?"
		# Get public IP and sanitize with grep
		get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
		read -p "Public IPv4 address / hostname [$get_public_ip]: " public_ip
		# If the checkip service is unavailable and user didn't provide input, ask again
		until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
			echo "Invalid input."
			read -p "Public IPv4 address / hostname: " public_ip
		done
		[[ -z "$public_ip" ]] && public_ip="$get_public_ip"
	fi
	# If system has a single IPv6, it is selected automatically
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
	fi
	# If system has multiple IPv6, ask the user to select one
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
		number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
		echo
		echo "Which IPv6 address should be used?"
		ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
		read -p "IPv6 address [1]: " ip6_number
		until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
			echo "$ip6_number: invalid selection."
			read -p "IPv6 address [1]: " ip6_number
		done
		[[ -z "$ip6_number" ]] && ip6_number="1"
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
	fi
	echo
	echo "What port should WireGuard listen to?"
	read -p "Port [51820]: " port
	until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
		echo "$port: invalid port."
		read -p "Port [51820]: " port
	done
	[[ -z "$port" ]] && port="51820"
	echo
	echo "Enter a name for the first client:"
	read -p "Name [client]: " unsanitized_client
	# Allow a limited set of characters to avoid conflicts
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	[[ -z "$client" ]] && client="client"
	echo
	echo "WireGuard installation is ready to begin."

	read -n1 -r -p "Press any key to continue..."
	# Install WireGuard
	# Set up the WireGuard kernel module
	if [[ "$os" == "ubuntu" ]]; then
		# Ubuntu
		apt-get update
		apt-get install -y wireguard qrencode $firewall
	elif [[ "$os" == "debian" && "$os_version" -eq 10 ]]; then
		# Debian 10
		if ! grep -qs '^deb .* buster-backports main' /etc/apt/sources.list /etc/apt/sources.list.d/*.list; then
			echo "deb http://deb.debian.org/debian buster-backports main" >> /etc/apt/sources.list
		fi
		apt-get update
		# Try to install kernel headers for the running kernel and avoid a reboot. This
		# can fail, so it's important to run separately from the other apt-get command.
		apt-get install -y linux-headers-"$(uname -r)"
		# There are cleaner ways to find out the $architecture, but we require an
		# specific format for the package name and this approach provides what we need.
		architecture=$(dpkg --get-selections 'linux-image-*-*' | cut -f 1 | grep -oE '[^-]*$' -m 1)
		# linux-headers-$architecture points to the latest headers. We install it
		# because if the system has an outdated kernel, there is no guarantee that old
		# headers were still downloadable and to provide suitable headers for future
		# kernel updates.
		apt-get install -y linux-headers-"$architecture"
		apt-get install -y wireguard qrencode $firewall
	elif [[ "$os" == "centos" && "$os_version" -eq 8 ]]; then
		# CentOS 8
		dnf install -y epel-release elrepo-release
		dnf install -y kmod-wireguard wireguard-tools qrencode $firewall
		mkdir -p /etc/wireguard/
	elif [[ "$os" == "centos" && "$os_version" -eq 7 ]]; then
		# CentOS 7
		yum install -y epel-release https://www.elrepo.org/elrepo-release-7.el7.elrepo.noarch.rpm
		yum install -y yum-plugin-elrepo
		yum install -y kmod-wireguard wireguard-tools qrencode $firewall
		mkdir -p /etc/wireguard/
	elif [[ "$os" == "fedora" ]]; then
		# Fedora
		dnf install -y wireguard-tools qrencode $firewall
		mkdir -p /etc/wireguard/
	fi
	# Generate wg0.conf
	cat << EOF > /etc/wireguard/wg0.conf
# Do not alter the commented lines
# They are used by wireguard-install
# ENDPOINT $([[ -n "$public_ip" ]] && echo "$public_ip" || echo "$ip")

[Interface]
Address = 10.7.0.1/16$([[ -n "$ip6" ]] && echo ", fddd:2c4:2c4:2c4::1/64")
PrivateKey = $(wg genkey)
ListenPort = $port

EOF
	chmod 600 /etc/wireguard/wg0.conf
	# Enable net.ipv4.ip_forward for the system
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/30-wireguard-forward.conf
	# Enable without waiting for a reboot or service restart
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if [[ -n "$ip6" ]]; then
		# Enable net.ipv6.conf.all.forwarding for the system
		echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/30-wireguard-forward.conf
		# Enable without waiting for a reboot or service restart
		echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
	fi
	new_client_setup
	# Enable and start the wg-quick service
	systemctl enable --now wg-quick@wg0.service
	echo
	qrencode -t UTF8 < "$PWD/client/$client.conf"
	echo -e '\xE2\x86\x91 That is a QR code containing the client configuration.'
	echo
	# If the kernel module didn't load, system probably had an outdated kernel
	# We'll try to help, but will not will not force a kernel upgrade upon the user
	if [[ ! "$is_container" -eq 0 ]] && ! modprobe -nq wireguard; then
		echo "Warning!"
		echo "Installation was finished, but the WireGuard kernel module could not load."
		if [[ "$os" == "ubuntu" && "$os_version" -eq 1804 ]]; then
		echo 'Upgrade the kernel and headers with "apt-get install linux-generic" and restart.'
		elif [[ "$os" == "debian" && "$os_version" -eq 10 ]]; then
		echo "Upgrade the kernel with \"apt-get install linux-image-$architecture\" and restart."
		elif [[ "$os" == "centos" && "$os_version" -le 8 ]]; then
			echo "Reboot the system to load the most recent kernel."
		fi
	else
		echo "Finished!"
	fi
	echo
	echo "The client configuration is available in:" "$PWD/client/$client.conf"
	echo "New clients can be added by running this script again."
else
	clear
	echo "WireGuard is already installed."
	echo
	echo "Select an option:"
	echo "   1) Add a new client"
	echo "   2) Remove an existing client"
	echo "   3) Remove WireGuard"
	echo "   4) Exit"
	read -p "Option: " option
	until [[ "$option" =~ ^[1-4]$ ]]; do
		echo "$option: invalid selection."
		read -p "Option: " option
	done
	case "$option" in
		1)
			echo
			echo "Provide a name for the client:"
			read -p "Name: " unsanitized_client
			# Allow a limited set of characters to avoid conflicts
			client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			while [[ -z "$client" ]] || grep -q "^# BEGIN_PEER $client$" /etc/wireguard/wg0.conf; do
				echo "$client: invalid name."
				read -p "Name: " unsanitized_client
				client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			done
			echo
			new_client_setup
			# Append new client configuration to the WireGuard interface
			wg addconf wg0 <(sed -n "/^# BEGIN_PEER $client/,/^# END_PEER $client/p" /etc/wireguard/wg0.conf)
			echo
			qrencode -t UTF8 < "$PWD/client/$client.conf"
			echo -e '\xE2\x86\x91 That is a QR code containing your client configuration.'
			echo
			echo "$client added. Configuration available in:" "$PWD/client/$client.conf"
			exit
		;;
		2)
			# This option could be documented a bit better and maybe even be simplified
			# ...but what can I say, I want some sleep too
			number_of_clients=$(grep -c '^# BEGIN_PEER' /etc/wireguard/wg0.conf)
			if [[ "$number_of_clients" = 0 ]]; then
				echo
				echo "There are no existing clients!"
				exit
			fi
			echo
			echo "Select the client to remove:"
			grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | nl -s ') '
			read -p "Client: " client_number
			until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
				echo "$client_number: invalid selection."
				read -p "Client: " client_number
			done
			client=$(grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | sed -n "$client_number"p)
			echo
			read -p "Confirm $client removal? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: invalid selection."
				read -p "Confirm $client removal? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				# The following is the right way to avoid disrupting other active connections:
				# Remove from the live interface
				wg set wg0 peer "$(sed -n "/^# BEGIN_PEER $client$/,\$p" /etc/wireguard/wg0.conf | grep -m 1 PublicKey | cut -d " " -f 3)" remove
				# Remove from the configuration file
				sed -i "/^# BEGIN_PEER $client/,/^# END_PEER $client/d" /etc/wireguard/wg0.conf
				echo
				echo "$client removed!"
			else
				echo
				echo "$client removal aborted!"
			fi
			exit
		;;
		3)
			echo
			read -p "Confirm WireGuard removal? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: invalid selection."
				read -p "Confirm WireGuard removal? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				systemctl disable --now wg-quick@wg0.service
				rm -f /etc/systemd/system/wg-quick@wg0.service.d/boringtun.conf
				rm -f /etc/sysctl.d/30-wireguard-forward.conf
				# Different packages were installed if the system was containerized or not
				if [[ ! "$is_container" -eq 0 ]]; then
					if [[ "$os" == "ubuntu" ]]; then
						# Ubuntu
						rm -rf /etc/wireguard/
						apt-get remove --purge -y wireguard wireguard-tools
					elif [[ "$os" == "debian" && "$os_version" -eq 10 ]]; then
						# Debian 10
						rm -rf /etc/wireguard/
						apt-get remove --purge -y wireguard wireguard-dkms wireguard-tools
					elif [[ "$os" == "centos" && "$os_version" -eq 8 ]]; then
						# CentOS 8
						rm -rf /etc/wireguard/
						dnf remove -y kmod-wireguard wireguard-tools
					elif [[ "$os" == "centos" && "$os_version" -eq 7 ]]; then
						# CentOS 7
						rm -rf /etc/wireguard/
						yum remove -y kmod-wireguard wireguard-tools
					elif [[ "$os" == "fedora" ]]; then
						# Fedora
						rm -rf /etc/wireguard/
						dnf remove -y wireguard-tools
					fi
				else
					{ crontab -l 2>/dev/null | grep -v '/usr/local/sbin/boringtun-upgrade' ; } | crontab -
					if [[ "$os" == "ubuntu" ]]; then
						# Ubuntu
						rm -rf /etc/wireguard/
						apt-get remove --purge -y wireguard-tools
					elif [[ "$os" == "debian" && "$os_version" -eq 10 ]]; then
						# Debian 10
						rm -rf /etc/wireguard/
						apt-get remove --purge -y wireguard-tools
					elif [[ "$os" == "centos" && "$os_version" -eq 8 ]]; then
						# CentOS 8
						rm -rf /etc/wireguard/
						dnf remove -y wireguard-tools
					elif [[ "$os" == "centos" && "$os_version" -eq 7 ]]; then
						# CentOS 7
						rm -rf /etc/wireguard/
						yum remove -y wireguard-tools
					elif [[ "$os" == "fedora" ]]; then
						# Fedora
						rm -rf /etc/wireguard/
						dnf remove -y wireguard-tools
					fi
					rm -f /usr/local/sbin/boringtun /usr/local/sbin/boringtun-upgrade
				fi
				echo
				echo "WireGuard removed!"
			else
				echo
				echo "WireGuard removal aborted!"
			fi
			exit
		;;
		4)
			exit
		;;
	esac
fi
