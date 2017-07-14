#! /bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#===============================================================================================
#   System Required:  CentOS6.x/7 (32bit/64bit) or Ubuntu
#   Description:  Install IKEV2 VPN for CentOS and Ubuntu
#   Author: quericy
#   Intro:  https://quericy.me/blog/699
#===============================================================================================

clear
VER=1.2.0
echo "#############################################################"
echo "# Install IKEV2 VPN for CentOS6.x/7 (32bit/64bit) or Ubuntu or Debian7/8.*"
echo "# Intro: https://quericy.me/blog/699"
echo "#"
echo "# Author:quericy"
echo "#"
echo "# Version:$VER"
echo "#############################################################"
echo ""

__INTERACTIVE=""
if [ -t 1 ] ; then
    __INTERACTIVE="1"
fi

__green(){
    if [ "$__INTERACTIVE" ] ; then
        printf '\033[1;31;32m'
    fi
    printf -- "$1"
    if [ "$__INTERACTIVE" ] ; then
        printf '\033[0m'
    fi
}

__red(){
    if [ "$__INTERACTIVE" ] ; then
        printf '\033[1;31;40m'
    fi
    printf -- "$1"
    if [ "$__INTERACTIVE" ] ; then
        printf '\033[0m'
    fi
}

__yellow(){
    if [ "$__INTERACTIVE" ] ; then
        printf '\033[1;31;33m'
    fi
    printf -- "$1"
    if [ "$__INTERACTIVE" ] ; then
        printf '\033[0m'
    fi
}

# Install IKEV2
function install_ikev2(){
    rootness
    disable_selinux
    apt_install
    get_my_ip
    pre_install
    download_files
    setup_strongswan
    get_key
    configure_ipsec
    configure_strongswan
    configure_secrets
    SNAT_set
    iptables_check
    install_pptp
    install_ovpn
    success_info
}

# Make sure only root can run our script
function rootness(){
if [[ $EUID -ne 0 ]]; then
   echo "Error:This script must be run as root!" 1>&2
   exit 1
fi
}

# Disable selinux
function disable_selinux(){
if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
    sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
    setenforce 0
fi
}

#install necessary lib
function apt_install(){
    apt-get -y update
    apt-get -y install libpam0g-dev libssl-dev make gcc curl
}

# Get IP address of the server
function get_my_ip(){
    echo "Preparing, Please wait a moment..."
    IP=`curl -s checkip.dyndns.com | cut -d' ' -f 6  | cut -d'<' -f 1`
    if [ -z $IP ]; then
        IP=`curl -s ifconfig.me/ip`
    fi
}

# Pre-installation settings
function pre_install(){
    echo "#############################################################"
    echo "# Install IKEV2 VPN for CentOS6.x/7 (32bit/64bit) or Ubuntu or Debian7/8.*"
    echo "# Intro: https://quericy.me/blog/699"
    echo "#"
    echo "# Author:quericy"
    echo "#"
    echo "# Version:$VER"
    echo "#############################################################"
    echo "your VPS is Xen、KVM"
    os="1"
    os_str="Xen、KVM"
    echo "please input the ip (or domain) of your VPS:"
    read -p "ip or domain(default_value:${IP}):" vps_ip
    if [ "$vps_ip" = "" ]; then
        vps_ip=$IP
    fi

    echo "Would you want to import existing cert? You NEED copy your cert file to the same directory of this script"
    read -p "yes or no?(default_value:no):" have_cert
    if [ "$have_cert" = "yes" ]; then
        have_cert="1"
    else
        have_cert="0"
        echo "please input the cert country(C):"
        read -p "C(default value:com):" my_cert_c
        if [ "$my_cert_c" = "" ]; then
            my_cert_c="com"
        fi
        echo "please input the cert organization(O):"
        read -p "O(default value:myvpn):" my_cert_o
        if [ "$my_cert_o" = "" ]; then
            my_cert_o="myvpn"
        fi
        echo "please input the cert common name(CN):"
        read -p "CN(default value:VPN CA):" my_cert_cn
        if [ "$my_cert_cn" = "" ]; then
            my_cert_cn="VPN CA"
        fi
    fi

    echo "####################################"
    get_char(){
        SAVEDSTTY=`stty -g`
        stty -echo
        stty cbreak
        dd if=/dev/tty bs=1 count=1 2> /dev/null
        stty -raw
        stty echo
        stty $SAVEDSTTY
    }
    echo "Please confirm the information:"
    echo ""
    echo -e "the type of your server: [$(__green $os_str)]"
    echo -e "the ip(or domain) of your server: [$(__green $vps_ip)]"
    if [ "$have_cert" = "1" ]; then
        echo -e "$(__yellow "These are the certificate you MUST be prepared:")"
        echo -e "[$(__green "ca.cert.pem")]:The CA cert or the chain cert."
        echo -e "[$(__green "server.cert.pem")]:Your server cert."
        echo -e "[$(__green "server.pem")]:Your  key of the server cert."
        echo -e "[$(__yellow "Please copy these file to the same directory of this script before start!")]"
    else
        echo -e "the cert_info:[$(__green "C=${my_cert_c}, O=${my_cert_o}")]"
    fi
    echo ""
    echo "Press any key to start...or Press Ctrl+C to cancel"
    char=`get_char`
    #Current folder
    cur_dir=`pwd`
    cd $cur_dir
}


# Download strongswan
function download_files(){
    strongswan_version='strongswan-5.5.1'
    strongswan_file="$strongswan_version.tar.gz"
    if [ -f $strongswan_file ];then
        echo -e "$strongswan_file [$(__green "found")]"
    else
        if ! wget --no-check-certificate https://download.strongswan.org/$strongswan_file;then
            echo "Failed to download $strongswan_file"
            exit 1
        fi
    fi
    tar xzf $strongswan_file
    if [ $? -eq 0 ];then
        cd $cur_dir/$strongswan_version/
    else
        echo ""
        echo "Unzip $strongswan_file failed! Please visit https://quericy.me/blog/699 and contact."
        exit 1
    fi
}

# configure and install strongswan
function setup_strongswan(){
    if [ "$os" = "1" ]; then
        ./configure  --enable-eap-identity --enable-eap-md5 \
--enable-eap-mschapv2 --enable-eap-tls --enable-eap-ttls --enable-eap-peap  \
--enable-eap-tnc --enable-eap-dynamic --enable-eap-radius --enable-xauth-eap  \
--enable-xauth-pam  --enable-dhcp  --enable-openssl  --enable-addrblock --enable-unity  \
--enable-certexpire --enable-radattr --enable-swanctl --enable-openssl --disable-gmp

    else
        ./configure  --enable-eap-identity --enable-eap-md5 \
--enable-eap-mschapv2 --enable-eap-tls --enable-eap-ttls --enable-eap-peap  \
--enable-eap-tnc --enable-eap-dynamic --enable-eap-radius --enable-xauth-eap  \
--enable-xauth-pam  --enable-dhcp  --enable-openssl  --enable-addrblock --enable-unity  \
--enable-certexpire --enable-radattr --enable-swanctl --enable-openssl --disable-gmp --enable-kernel-libipsec

    fi
    make; make install
}

# configure cert and key
function get_key(){
    cd $cur_dir
    if [ ! -d my_key ];then
        mkdir my_key
    fi
    if [ "$have_cert" = "1" ]; then
        import_cert
    else
        create_cert
    fi

    echo "####################################"
    get_char(){
        SAVEDSTTY=`stty -g`
        stty -echo
        stty cbreak
        dd if=/dev/tty bs=1 count=1 2> /dev/null
        stty -raw
        stty echo
        stty $SAVEDSTTY
    }
    cp -f ca.cert.pem /usr/local/etc/ipsec.d/cacerts/
    cp -f server.cert.pem /usr/local/etc/ipsec.d/certs/
    cp -f server.pem /usr/local/etc/ipsec.d/private/
    cp -f client.cert.pem /usr/local/etc/ipsec.d/certs/
    cp -f client.pem  /usr/local/etc/ipsec.d/private/
    echo "Cert copy completed"
}

# import cert if user has ssl certificate
function import_cert(){
   cd $cur_dir
   if [ -f ca.cert.pem ];then
        cp -f ca.cert.pem my_key/ca.cert.pem
        echo -e "ca.cert.pem [$(__green "found")]"
    else
        echo -e "ca.cert.pem [$(__red "Not found!")]"
        exit
    fi
    if [ -f server.cert.pem ];then
        cp -f server.cert.pem my_key/server.cert.pem
        cp -f server.cert.pem my_key/client.cert.pem
        echo -e "server.cert.pem [$(__green "found")]"
        echo -e "client.cert.pem [$(__green "auto create")]"
    else
        echo -e "server.cert.pem [$(__red "Not found!")]"
        exit
    fi
    if [ -f server.pem ];then
        cp -f server.pem my_key/server.pem
        cp -f server.pem my_key/client.pem
        echo -e "server.pem [$(__green "found")]"
        echo -e "client.pem [$(__green "auto create")]"
    else
        echo -e "server.pem [$(__red "Not found!")]"
        exit
    fi
    cd my_key
}

# auto create certificate
function create_cert(){
    cd $cur_dir
    cd my_key
    ipsec pki --gen --outform pem > ca.pem
    ipsec pki --self --in ca.pem --dn "C=${my_cert_c}, O=${my_cert_o}, CN=${my_cert_cn}" --ca --outform pem >ca.cert.pem
    ipsec pki --gen --outform pem > server.pem
    ipsec pki --pub --in server.pem | ipsec pki --issue --cacert ca.cert.pem \
    --cakey ca.pem --dn "C=${my_cert_c}, O=${my_cert_o}, CN=${vps_ip}" \
    --san="${vps_ip}" --flag serverAuth --flag ikeIntermediate \
    --outform pem > server.cert.pem
    ipsec pki --gen --outform pem > client.pem
    ipsec pki --pub --in client.pem | ipsec pki --issue --cacert ca.cert.pem --cakey ca.pem --dn "C=${my_cert_c}, O=${my_cert_o}, CN=VPN Client" --outform pem > client.cert.pem
    echo "configure the pkcs12 cert password(Can be empty):"
    openssl pkcs12 -export -inkey client.pem -in client.cert.pem -name "client" -certfile ca.cert.pem -caname "${my_cert_cn}"  -out client.cert.p12
}

# configure the ipsec.conf
function configure_ipsec(){
 cat > /usr/local/etc/ipsec.conf<<-EOF
config setup
    uniqueids=never 

conn iOS_cert
    keyexchange=ikev1
    fragmentation=yes
    left=%defaultroute
    leftauth=pubkey
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    right=%any
    rightauth=pubkey
    rightauth2=xauth
    rightsourceip=10.31.2.0/24
    rightcert=client.cert.pem
    auto=add

conn android_xauth_psk
    keyexchange=ikev1
    left=%defaultroute
    leftauth=psk
    leftsubnet=0.0.0.0/0
    right=%any
    rightauth=psk
    rightauth2=xauth
    rightsourceip=10.31.2.0/24
    auto=add

conn networkmanager-strongswan
    keyexchange=ikev2
    left=%defaultroute
    leftauth=pubkey
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    right=%any
    rightauth=eap-radius
    rightsourceip=10.31.2.0/24
    rightcert=client.cert.pem
    auto=add

conn ios_ikev2
    keyexchange=ikev2
    ike=aes256-sha256-modp2048,3des-sha1-modp2048,aes256-sha1-modp2048!
    esp=aes256-sha256,3des-sha1,aes256-sha1!
    rekey=no
    left=%defaultroute
    leftid=${vps_ip}
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    right=%any
    rightauth=eap-radius
    rightsourceip=10.31.2.0/24
    rightsendcert=never
    eap_identity=%any
    dpdaction=clear
    fragmentation=yes
    auto=add

conn windows7
    keyexchange=ikev2
    ike=aes256-sha1-modp1024!
    rekey=no
    left=%defaultroute
    leftauth=pubkey
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    right=%any
    rightauth=eap-radius
    rightsourceip=10.31.2.0/24
    rightsendcert=never
    eap_identity=%any
    auto=add

EOF
}

# configure the strongswan.conf
function configure_strongswan(){
 cat > /usr/local/etc/strongswan.conf<<-EOF
 charon {
        load_modular = yes
        duplicheck.enable = no
        compress = yes
        plugins {
                include strongswan.d/charon/*.conf
        }
        dns1 = 8.8.8.8
        dns2 = 8.8.4.4
        nbns1 = 8.8.8.8
        nbns2 = 8.8.4.4
}
include strongswan.d/*.conf
EOF
}

# configure the ipsec.secrets
function configure_secrets(){
    cat > /usr/local/etc/ipsec.secrets<<-EOF
: RSA server.pem
: PSK "myPSKkey"
: XAUTH "myXAUTHPass"
myUserName %any : EAP "myUserPass"
EOF
}

function SNAT_set(){
    echo "Use SNAT could implove the speed,but your server MUST have static ip address."
    read -p "yes or no?(default_value:no):" use_SNAT
    if [ "$use_SNAT" = "yes" ]; then
        use_SNAT_str="1"
        echo -e "$(__yellow "ip address info:")"
        ip address | grep inet
        echo "Some servers has elastic IP (AWS) or mapping IP.In this case,you should input the IP address which is binding in network interface."
        read -p "static ip or network interface ip (default_value:${IP}):" static_ip
    if [ "$static_ip" = "" ]; then
        static_ip=$IP
    fi
    else
        use_SNAT_str="0"
    fi
}

# iptables check
function iptables_check(){
    cat > /etc/sysctl.d/10-ipsec.conf<<-EOF
net.ipv4.ip_forward=1
EOF
    sysctl --system
    iptables_set
}

# iptables set
function iptables_set(){
    echo -e "$(__yellow "ip address info:")"
    ip address | grep inet
    echo "The above content is the network card information of your VPS."
    echo "[$(__yellow "Important")]Please enter the name of the interface which can be connected to the public network."
    if [ "$os" = "1" ]; then
            read -p "Network card interface(default_value:eth0):" interface
        if [ "$interface" = "" ]; then
            interface="eth0"
        fi
        iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
        iptables -A FORWARD -s 10.31.0.0/24  -j ACCEPT
        iptables -A FORWARD -s 10.31.1.0/24  -j ACCEPT
        iptables -A FORWARD -s 10.31.2.0/24  -j ACCEPT
        iptables -A INPUT -i $interface -p esp -j ACCEPT
        iptables -A INPUT -i $interface -p udp --dport 500 -j ACCEPT
        iptables -A INPUT -i $interface -p tcp --dport 500 -j ACCEPT
        iptables -A INPUT -i $interface -p udp --dport 4500 -j ACCEPT
        iptables -A INPUT -i $interface -p udp --dport 1701 -j ACCEPT
        iptables -A INPUT -i $interface -p tcp --dport 1723 -j ACCEPT
        #iptables -A FORWARD -j REJECT
        if [ "$use_SNAT_str" = "1" ]; then
            iptables -t nat -A POSTROUTING -s 10.31.0.0/24 -o $interface -j SNAT --to-source $static_ip
            iptables -t nat -A POSTROUTING -s 10.31.1.0/24 -o $interface -j SNAT --to-source $static_ip
            iptables -t nat -A POSTROUTING -s 10.31.2.0/24 -o $interface -j SNAT --to-source $static_ip
        else
            iptables -t nat -A POSTROUTING -s 10.31.0.0/24 -o $interface -j MASQUERADE
            iptables -t nat -A POSTROUTING -s 10.31.1.0/24 -o $interface -j MASQUERADE
            iptables -t nat -A POSTROUTING -s 10.31.2.0/24 -o $interface -j MASQUERADE
        fi
    else
        read -p "Network card interface(default_value:venet0):" interface
        if [ "$interface" = "" ]; then
            interface="venet0"
        fi
        iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
        iptables -A FORWARD -s 10.31.0.0/24  -j ACCEPT
        iptables -A FORWARD -s 10.31.1.0/24  -j ACCEPT
        iptables -A FORWARD -s 10.31.2.0/24  -j ACCEPT
        iptables -A INPUT -i $interface -p esp -j ACCEPT
        iptables -A INPUT -i $interface -p udp --dport 500 -j ACCEPT
        iptables -A INPUT -i $interface -p tcp --dport 500 -j ACCEPT
        iptables -A INPUT -i $interface -p udp --dport 4500 -j ACCEPT
        iptables -A INPUT -i $interface -p udp --dport 1701 -j ACCEPT
        iptables -A INPUT -i $interface -p tcp --dport 1723 -j ACCEPT
        #iptables -A FORWARD -j REJECT
        if [ "$use_SNAT_str" = "1" ]; then
            iptables -t nat -A POSTROUTING -s 10.31.0.0/24 -o $interface -j SNAT --to-source $static_ip
            iptables -t nat -A POSTROUTING -s 10.31.1.0/24 -o $interface -j SNAT --to-source $static_ip
            iptables -t nat -A POSTROUTING -s 10.31.2.0/24 -o $interface -j SNAT --to-source $static_ip
        else
            iptables -t nat -A POSTROUTING -s 10.31.0.0/24 -o $interface -j MASQUERADE
            iptables -t nat -A POSTROUTING -s 10.31.1.0/24 -o $interface -j MASQUERADE
            iptables -t nat -A POSTROUTING -s 10.31.2.0/24 -o $interface -j MASQUERADE
        fi
    fi
    if [ "$system_str" = "0" ]; then
        service iptables save
    else
        iptables-save > /etc/iptables.rules
        cat > /etc/network/if-up.d/iptables<<-EOF
#!/bin/sh
iptables-restore < /etc/iptables.rules
EOF
        chmod +x /etc/network/if-up.d/iptables
    fi
}

function install_pptp(){
  printhelp() {

echo "

Usage: sh setup.sh [OPTION]

If you are using custom password , Make sure its more than 8 characters. Otherwise it will generate random password for you. 

If you trying set password only. It will generate Default user with Random password. 

example: sudo bash setup.sh -u vpn -p mypass

Use without parameter [ sudo bash setup.sh ] to use default username and Random password


  -u,    --username             Enter the Username
  -p,    --password             Enter the Password
"
}

while [ "$1" != "" ]; do
  case "$1" in
    -u    | --username )             NAME=$2; shift 2 ;;
    -p    | --password )             PASS=$2; shift 2 ;;
    -h    | --help )            echo "$(printhelp)"; exit; shift; break ;;
  esac
done

if [ `id -u` -ne 0 ] 
then
  echo "Need root, try with sudo"
  exit 0
fi

apt-get -y install radiusclient1 pptpd || {
  echo "Could not install pptpd" 
  exit 1
}

#ubuntu has exit 0 at the end of the file.
sed -i '/^exit 0/d' /etc/rc.local

cat >> /etc/rc.local << END
echo 1 > /proc/sys/net/ipv4/ip_forward
#ssh channel
iptables -I INPUT -p tcp --dport 22 -j ACCEPT
#control channel
iptables -I INPUT -p tcp --dport 1723 -j ACCEPT
#gre tunnel protocol
iptables -I INPUT  --protocol 47 -j ACCEPT

iptables -t nat -A POSTROUTING -s 192.168.2.0/24 -d 0.0.0.0/0 -o eth0 -j MASQUERADE

#supposedly makes the vpn work better
iptables -I FORWARD -s 192.168.2.0/24 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j TCPMSS --set-mss 1356

END
sh /etc/rc.local

#no liI10oO chars in password

LEN=$(echo ${#PASS})

if [ -z "$PASS" ] || [ $LEN -lt 8 ] || [ -z "$NAME"]
then
   P1=`cat /dev/urandom | tr -cd abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789 | head -c 3`
   P2=`cat /dev/urandom | tr -cd abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789 | head -c 3`
   P3=`cat /dev/urandom | tr -cd abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789 | head -c 3`
   PASS="$P1-$P2-$P3"
fi

if [ -z "$NAME" ]
then
   NAME="vpn"
fi

cat >/etc/ppp/chap-secrets <<END
# Secrets for authentication using CHAP
# client server secret IP addresses
$NAME pptpd $PASS *
END
cat >/etc/pptpd.conf <<END
option /etc/ppp/options.pptpd
logwtmp
localip 192.168.2.1
remoteip 192.168.2.10-100
END
cat >/etc/ppp/options.pptpd <<END
name pptpd
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
require-mppe-128
ms-dns 8.8.8.8
ms-dns 8.8.4.4
proxyarp
lock
nobsdcomp 
novj
novjccomp
nologfd
END

apt-get -y install wget || {
  echo "Could not install wget, required to retrieve your IP address." 
  exit 1
}

#find out external ip 
IP=`wget -q -O - http://api.ipify.org`

if [ "x$IP" = "x" ]
then
  echo "============================================================"
  echo "  !!!  COULD NOT DETECT SERVER EXTERNAL IP ADDRESS  !!!"
else
  echo "============================================================"
  echo "Detected your server external ip address: $IP"
fi
echo   ""
echo   "VPN username = $NAME   password = $PASS"
echo   "============================================================"
exit 0
}

#radius config
#param $1 radius_server_ip $2 bash_path $3 ip_server $4 radius_share_key
function radius_config(){
# openvpn radius 配置
apt-get -y install libgcrypt11 libgcrypt11-dev build-essential
mkdir /etc/radiusplugin
cd /etc/radiusplugin/
wget http://www.nongnu.org/radiusplugin/radiusplugin_v2.1a_beta1.tar.gz
tar xvf radiusplugin_v2.1a_beta1.tar.gz
cd radiusplugin_v2.1a_beta1
make
mkdir /etc/openvpn/radius
cp -r radiusplugin.so /etc/openvpn/radius
cp -r "$2/radius.cnf" "/etc/openvpn/radius/"
sed -i "s/NAS-IP-Address=ip_server/NAS-IP-Address=$3/" "/etc/openvpn/radius/radius.cnf"
sed -i "s/name=radius_server_ip/name=$1/" "/etc/openvpn/radius/radius.cnf"
sed -i "s/sharedsecret=radius_share_key/name=$4/" "/etc/openvpn/radius/radius.cnf"
#pptp 
#配置radius
cd /etc/radiusclient 
wget https://www.mawenbao.com/static/resource/dictionary.microsoft
echo "INCLUDE /etc/radiusclient/dictionary.microsoft">>/etc/radiusclient/dictionary
echo "ATTRIBUTE Acct-Interim-Interval 85 integer">>/etc/radiusclient/dictionary
echo "$1 $4">>/etc/radiusclient/servers

sed -i "s/authserver localhost/authserver $1:1812/" "/etc/radiusclient/radiusclient.conf"
sed -i "s/acctserver localhost/acctserver $1:1813/" "/etc/radiusclient/radiusclient.conf"

echo "plugin radius.so">>/etc/ppp/options.pptpd
echo "plugin radius.so">>/etc/ppp/options.pptpd

#ikev2
cp -r "$2/eap-radius.conf" "/usr/local/etc/strongswan.d/charon/"
sed -i "s/secret = radius_share_key/secret = $4/" "/usr/local/etc/strongswan.d/charon/eap-radius.conf"
sed -i "s/address = radius_server_ip/secret = $1/" "/usr/local/etc/strongswan.d/charon/eap-radius.conf"

service pptpd restart
service openvpn restart
ipsec restart
}

function install_ovpn(){
apt-get -y install openvpn

# Ensure to be root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

# Ensure there are the prerequisites
for i in openvpn wget sed; do
  which $i > /dev/null
  if [ "$?" -ne 0 ]; then
    echo "Miss $i"
    exit
  fi
done

www=$1
user=$2
group=$3

# current path
base_path=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

printf "\n################## Server informations ##################\n"
read -p "Server Hostname/IP: " ip_server

read -p "Port [54]: " server_port

if [[ -z $server_port ]]; then
  server_port="54"
fi

printf "\n################## Setup OpenVPN ##################\n"

# Copy certificates and the server configuration in the openvpn directory

cp -r "$base_path/certs/"* "/etc/openvpn/"
cp -r "$base_path/server.conf" "/etc/openvpn/"
mkdir "/etc/openvpn/ccd"
sed -i "s/port 54/port $server_port/" "/etc/openvpn/server.conf"

nobody_group=$(id -ng nobody)
sed -i "s/group nogroup/group $nobody_group/" "/etc/openvpn/server.conf"

printf "\n################## Setup firewall ##################\n"

# Make ip forwading and make it persistent
echo 1 > "/proc/sys/net/ipv4/ip_forward"
echo "net.ipv4.ip_forward = 1" >> "/etc/sysctl.conf"

# Iptable rules
iptables -I FORWARD -i tun0 -j ACCEPT
iptables -I FORWARD -o tun0 -j ACCEPT
iptables -I OUTPUT -o tun0 -j ACCEPT

iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.8.0.2/24 -o eth0 -j MASQUERADE

read -p "radius_server_ip:" radius_server_ip
read -p "radius_share_key:" radius_share_key
radius_config $radius_server_ip $bash_path  $ip_server $radius_share_key
}

# echo the success info
function success_info(){
    echo "#############################################################"
    echo -e "#"
    echo -e "# [$(__green "Install Complete")]"
    echo -e "# Version:$VER"
    echo -e "# There is the default login info of your IPSec/IkeV2 VPN Service"
    echo -e "# UserName:$(__green " myUserName")"
    echo -e "# PassWord:$(__green " myUserPass")"
    echo -e "# PSK:$(__green " myPSKkey")"
    echo -e "# you should change default username and password in$(__green " /usr/local/etc/ipsec.secrets")"
    echo -e "# you cert:$(__green " ${cur_dir}/my_key/ca.cert.pem ")"
    if [ "$have_cert" = "1" ]; then
    echo -e "# you don't need to install cert if it's be trusted."
    else
    echo -e "# you must copy the cert to the client and install it."
    fi
    echo -e "#"
    echo -e "#############################################################"
    echo -e ""
}

# Initialization step
install_ikev2
