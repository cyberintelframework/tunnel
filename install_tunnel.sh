#!/bin/sh

# Defaults
CRONTAB=/etc/crontab
PREFIX=/opt/surfnetids
CONFDIR=/etc/surfnetids
OPENVPNLOC=/usr/sbin/openvpn

echo "Starting the installation of the SURF IDS tunnel server."

echo -ne "Use SURFnet IDS certificate defaults? [Y/n]: "
read CHOICE
case $CHOICE
in
  Y|y)
    break;;
  N|n) clear
    ;;
  *) echo -e "${YELLOW}Unkown choice. Try again.${NORMAL}"
    ;;
esac

if [ $CHOICE == "N" -o $CHOICE == "n" ]; then
  ########### Key size ###########
  echo -ne "Enter the key size [1024/2048]: "
  while :
  do
    read keysize
    if [ ! -z $keysize ]; then
      if [ $keysize == "1024" -o $keysize == "2048" ]; then
        break
      else
        echo -ne "Enter the key size [1024/2048]: "
      fi
    else
      echo -ne "Enter the key size [1024/2048]: "
    fi
  done
  ########### Country ###########
  echo -ne "Enter the country (2 character abbreviation): "
  while :
  do
    read keycountry
    if [ ! -z $keycountry ]; then
      break
    else
      echo -ne "Enter the country (2 character abbreviation): "
    fi
  done
  ########### Province ###########
  echo -ne "Enter the province: "
  while :
  do
    read keyprovince
    if [ ! -z $keyprovince ]; then
      break
    else
      echo -ne "Enter the province: "
    fi
  done
  ########### City ###########
  echo -ne "Enter the city: "
  while :
  do
    read keycity
    if [ ! -z $keycity ]; then
      break
    else
      echo -ne "Enter the city: "
    fi
  done
  ########### Organisation ###########
  echo -ne "Enter the organisation: "
  while :
  do
    read keyorg
    if [ ! -z "$keyorg" ]; then
      break
    else
      echo -ne "Enter the organisation: "
    fi
  done
  ########### Email ###########
  echo -ne "Enter the email address: "
  while :
  do
    read keyemail
    if [ ! -z $keyemail ]; then
      break
    else
      echo -ne "Enter the email address: "
    fi
  done

  echo -e "Generating new certificate configuration file."
  #################
  echo -e "D=$PREFIX" > $PREFIX/genkeys/vars.conf
  echo -e "genkeys=\$D/genkeys" >> $PREFIX/genkeys/vars.conf
  echo -e "serverkeys=\$D/serverkeys" >> $PREFIX/genkeys/vars.conf
  echo -e "clientkeys=\$D/clientkeys" >> $PREFIX/genkeys/vars.conf
  echo -e "" >> $PREFIX/genkeys/vars.conf
  echo -e "export D=$PREFIX" >> $PREFIX/genkeys/vars.conf
  echo -e "export KEY_CONFIG=$PREFIX/genkeys/openssl.cnf" >> $PREFIX/genkeys/vars.conf
  echo -e "export KEY_DIR=$PREFIX/serverkeys" >> $PREFIX/genkeys/vars.conf
  echo -e "export KEY_SIZE=$keysize" >> $PREFIX/genkeys/vars.conf
  echo -e "export KEY_COUNTRY=\"$keycountry\"" >> $PREFIX/genkeys/vars.conf
  echo -e "export KEY_PROVINCE=\"$keyprovince\"" >> $PREFIX/genkeys/vars.conf
  echo -e "export KEY_CITY=\"$keycity\"" >> $PREFIX/genkeys/vars.conf
  echo -e "export KEY_ORG=\"$keyorg\"" >> $PREFIX/genkeys/vars.conf
  echo -e "export KEY_EMAIL=\"$keyemail\"" >> $PREFIX/genkeys/vars.conf
  echo -e "export KEY_UNITNAME=\"SURFnet IDS\"" >> $PREFIX/genkeys/vars.conf
  echo -e "export KEY_COMMONNAME=server" >> $PREFIX/genkeys/vars.conf
fi

####### Creating sever keys #############
. $PREFIX/genkeys/servervars
if [ ! -e $PREFIX/serverkeys/ca.crt ]; then
  $PREFIX/genkeys/build-ca
else
  echo -e "Root certificate already exists. Not generating new."
fi
if [ ! -e $PREFIX/serverkeys/tunserver.crt ]; then
  $PREFIX/genkeys/build-key-server tunserver
else
  echo -e "Server certificate already exists. Not generating new."
fi
if [ ! -e $PREFIX/serverkeys/dh1024.pem ]; then
  $PREFIX/genkeys/build-dh
else
  echo -e "Diffie-Hellman parameters already exist. Not generating new."
fi

####### Creating scripts certificate ###########
if [ ! -e $PREFIX/updates/scripts.crt ]; then
  . $PREFIX/genkeys/scriptvars
  $PREFIX/genkeys/build-ca
  mv $PREFIX/updates/ca.key $PREFIX/scriptkeys/scripts.key
  mv $PREFIX/updates/ca.crt $PREFIX/updates/scripts.crt
else
  echo -e "Scripts certificate already exists. Not generating new."
fi

####### Modifying dhcp3 files ###########
if [ -r /etc/dhcp3/dhclient.conf ]; then
  mv -f /etc/dhcp3/dhclient.conf /etc/dhcp3/dhclient.conf.old
  mv -f $PREFIX/dhclient.conf /etc/dhcp3/
fi

####### Setting up xinetd configuration for OpenVPN ##############
IPADDR=`ifconfig | grep "inet addr" | grep -v 127.0.0.1 | head -n1 | awk '{print $2}' | cut -d":" -f2`
echo "Setting up xinetd. Enter the IP address of your main network card: [$IPADDR]"

while :
do
  read IPADDRESS
  if [ -z $IPADDRESS ]; then
    break
  else
    IPADDR=$IPADDRESS
    break
  fi
done

echo -e "service openvpn" > $PREFIX/xinetd.openvpn
echo -e "{" >> $PREFIX/xinetd.openvpn
echo -e "  disable		= no" >> $PREFIX/xinetd.openvpn
echo -e "  type			= UNLISTED" >> $PREFIX/xinetd.openvpn
echo -e "  port			= 1194" >> $PREFIX/xinetd.openvpn
echo -e "  socket_type		= stream" >> $PREFIX/xinetd.openvpn 
echo -e "  protocol		= tcp" >> $PREFIX/xinetd.openvpn
echo -e "  wait			= no" >> $PREFIX/xinetd.openvpn
echo -e "  bind			= $IPADDR" >> $PREFIX/xinetd.openvpn
echo -e "  user			= root" >> $PREFIX/xinetd.openvpn
echo -e "  server		= $OPENVPNLOC" >> $PREFIX/xinetd.openvpn
echo -e "  server_args		= --config /etc/openvpn/server.conf" >> $PREFIX/xinetd.openvpn
echo -e "}" >> $PREFIX/xinetd.openvpn

if [ -r /etc/xinetd.d/openvpn ]; then
  mv -f /etc/xinetd.d/openvpn /etc/xinetd.d/openvpn.old
fi
mv -f $PREFIX/xinetd.openvpn /etc/xinetd.d/openvpn
/etc/init.d/xinetd restart

####### Setting up OpenVPN configuration ###############
echo "status $PREFIX/log/openvpn-status.log" >> $PREFIX/openvpn-server.conf

echo "up $PREFIX/scripts/up.pl" >> $PREFIX/openvpn-server.conf
echo "down $PREFIX/scripts/down.pl" >> $PREFIX/openvpn-server.conf
echo "ipchange $PREFIX/scripts/setmac.pl" >> $PREFIX/openvpn-server.conf

echo "dh $PREFIX/serverkeys/dh1024.pem" >> $PREFIX/openvpn-server.conf
echo "ca $PREFIX/serverkeys/ca.crt" >> $PREFIX/openvpn-server.conf
echo "cert $PREFIX/serverkeys/tunserver.crt" >> $PREFIX/openvpn-server.conf
echo "key $PREFIX/serverkeys/tunserver.key" >> $PREFIX/openvpn-server.conf

if [ -d /etc/openvpn/ ]; then
  if [ -r /etc/openvpn/server.conf ]; then
    mv -f /etc/openvpn/server.conf /etc/openvpn/server.conf.old
  fi
  cp $PREFIX/openvpn-server.conf /etc/openvpn/server.conf
fi

####### Creating /dev/net/tun #########
if [ ! -d /dev/net/ ]; then
  mkdir /dev/net/
fi
if [ ! -r /dev/net/tun ]; then
  mknod /dev/net/tun c 10 200
fi

####### Setting up Crontab ##########
croncheck=`cat $CRONTAB | grep "scanbinaries\.pl" | wc -l`
if [ $croncheck == 0 ]; then
  cat $PREFIX/crontab.tn >> $CRONTAB
else
  echo -e "No crontab modifications needed."
fi

####### Setting up Apache-ssl configuration ##########
cp $PREFIX/surfnetids-tn-apache.conf /etc/apache-ssl/conf.d/

if [ ! -e $PREFIX/.htpasswd ]; then
  echo -e "Setting up sensor authentication for apache-ssl."
  htpasswd -c -m /opt/surfnetids/.htpasswd idssensor
else
  echo -e "Sensor authentication file already exists. Not generating new."
fi

####### Restarting apache-ssl
/etc/init.d/apache-ssl restart

####### Setting up permissions ###########
chmod 777 $PREFIX/clientkeys/
chmod 777 $PREFIX/serverkeys/
chmod +r $PREFIX/serverkeys/ca.key

####### Setting up iproute2 ###########
if [ -r /etc/iproute2/rt_tables ]; then
  iproutecheck=`cat /etc/iproute2/rt_tables | wc -l`
  if [ $iproutecheck -gt 200 ]; then
    echo -e "No need to modify /etc/iproute2/rt_tables."
  else
    cp /etc/iproute2/rt_tables /etc/iproute2/rt_tables.old
    for ((i=20;i<221;i++)) {
      n=`echo $i -20 | bc`
      echo -e "$i		tap$n" >> /etc/iproute2/rt_tables
    }
  fi
else
  echo -e "Error: Could not modify /etc/iproute2/rt_tables"
fi

####### Cleaning up ###########
rm -f $PREFIX/crontab.tn
rm -f $PREFIX/surfnetids-tn-apache.conf
rm -f $PREFIX/openvpn-server.conf

echo -e "#####################################"
echo -e "# SURFnet IDS installation complete #"
echo -e "#####################################"
echo -e ""
echo -e "For extra security keep the scripts key (/opt/surfnetids/scriptkeys/scripts.key) somewhere safe (offline)."
echo -e ""
echo -e "Configuration files to edit:"
echo -e "  $CONFDIR/surfnetids-tn.conf"
echo -e "  /etc/crontab"
echo -e ""
echo -e "For more information go to http://ids.surfnet.nl/"
