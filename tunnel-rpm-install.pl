#!/usr/bin/perl

#############################
# Configuration info
#############################

# These are the values that will be used for the creation of the certificates
$key_size = "1024";
$key_country = "";
$key_prov = "";
$key_city = "";
$key_org = "";
$key_email = '';

# This is the IP address that xinetd will be listening on for incoming
# OpenVPN connections. This HAS TO BE an ip address.
$xinetd = "";

# This is the password that is used for the sensors to connect to the 
# tunnel server via https. This password will go into the .htaccess.
$htpasswd = "";

# The FQDN hostname of your server (if it has any)
# If it doesn't have a FQDN, enter the same address as $xinetd
$hostname = "";

#############################
# DO NOT EDIT BELOW
#############################
$targetdir = "/opt/surfnetids/";
$ssldir = "/etc/httpd/surfidsssl/";

if ("$key_size" eq "") { print "Key size was empty!\n"; exit 1; }
if ("$key_country" eq "") { print "Key country was empty!\n"; exit 1; }
if ("$key_prov" eq "") { print "Key province was empty!\n"; exit 1; }
if ("$key_city" eq "") { print "Key city was empty!\n"; exit 1; }
if ("$key_org" eq "") { print "Key organisation was empty!\n"; exit 1; }
if ("$key_email" eq "") { print "Key email was empty!\n"; exit 1; }
if ("$xinetd" eq "") { print "Xinetd listener address was empty!\n"; exit 1; }
if ("$htpasswd" eq "") { print ".htaccess password was empty!\n"; exit 1; }
if ("$hostname" eq "") { print ".htaccess password was empty!\n"; exit 1; }

if (! -e "$targetdir/serverkeys/index.txt") {
  `touch $targetdir/serverkeys/index.txt`;
}
if (! -e "$targetdir/serverkeys/index.txt.old") {
  `touch $targetdir/serverkeys/index.txt.old`;
}
if (! -e "$targetdir/serverkeys/index.txt.attr") {
  `echo "unique_subject = no" > $targetdir/serverkeys/index.txt.attr`;
}
if (! -e "$targetdir/serverkeys/index.txt.attr.old") {
  `echo "unique_subject = no" > $targetdir/serverkeys/index.txt.attr.old`;
}
if (! -e "$targetdir/serverkeys/serial") {
  `echo "01" > $targetdir/serverkeys/serial`;
}
if (! -e "$targetdir/serverkeys/serial.old") {
  `echo "00" > $targetdir/serverkeys/serial.old`;
}

if (-e "$targetdir/genkeys/vars.conf") {
    $perl = `grep perl $targetdir/genkeys/vars.conf | wc -l 2>>$logfile`;
    chomp($perl);
    if ($perl == 0) {
        `mv -f $targetdir/genkeys/vars.conf $targetdir/genkeys/old_vars.conf  2>>$logfile`;
    }
}

if (! -e "$targetdir/genkeys/vars.conf") {
    `cp $targetdir/genkeys/vars.conf.dist $targetdir/genkeys/vars.conf`;

    # Setting up the vars.conf
    open(VARS, ">>$targetdir/genkeys/vars.conf");
    print VARS "\n";
    print VARS "\$key_config = \"\$c_surfidsdir/genkeys/openssl.cnf\";\n";
    print VARS "\$key_dir = \"\$c_surfidsdir/serverkeys/\";\n";
    print VARS "\$key_size = \"$key_size\";\n";
    print VARS "\$key_country = \"$key_country\";\n";
    print VARS "\$key_province = \"$key_prov\";\n";
    print VARS "\$key_city = \"$key_city\";\n";
    print VARS "\$key_org = \"$key_org\";\n";
    print VARS "\$key_email = \"$key_email\";\n";
    print VARS "\$key_unitname = \"SURFnet IDS\";\n";
    print VARS "\$key_commonname = \"server\";\n";
    print VARS "\$key_certtype = \"client\";\n";
    close(VARS);
} else {
    require "$targetdir/genkeys/vars.conf";
}

# Exporting variables to the environment
$ENV{"D"} = "$targetdir";
$ENV{"KEY_CONFIG"} = "$targetdir/genkeys/openssl.cnf";
$ENV{"KEY_DIR"} = "$targetdir/serverkeys/";
$ENV{"KEY_SIZE"} = $key_size;
$ENV{"KEY_COUNTRY"} = "$key_country";
$ENV{"KEY_PROVINCE"} = "$key_prov";
$ENV{"KEY_CITY"} = "$key_city";
$ENV{"KEY_ORG"} = "$key_org";
$ENV{"KEY_EMAIL"} = "$key_email";
$ENV{"KEY_UNITNAME"} = "SURFnet IDS";
$ENV{"KEY_COMMONNAME"} = "server";
$ENV{"KEY_CERTTYPE"} = "server";

# Generating ca.crt
if (! -e "$targetdir/serverkeys/ca.crt") {
    print "==== Starting CA creation! ====\n";
    `$targetdir/genkeys/build-ca`;
} else {
    print "ca.crt already exists, skipping generation!\n";
}

# Generating server certificate
if (! -e "$targetdir/serverkeys/tunserver.crt") {
    $ENV{"KEY_COMMONNAME"} = "$hostname";
    $ENV{"KEY_CERTTYPE"} = "server";

    print "==== Starting tuncert creation! ====\n";
    `$targetdir/genkeys/build-key-server tunserver`;
} else {
    print "tunserver.crt already exists, skipping generation!\n";
}

# Generate Diffie-Hellman parameters
if (! -e "$targetdir/serverkeys/dh${key_size}.pem") {
    print "==== Starting DH creation! ====\n";
    `$targetdir/genkeys/build-dh`;
} else {
    print "Diffie-Hellman parameters already exist, skipping generation!\n";
}

# Setting up xinetd
open(XINETD, ">/etc/surfnetids/xinetd.conf");
print XINETD "service openvpn\n";
print XINETD "\{\n";
print XINETD "  disable              = no\n";
print XINETD "  type                 = UNLISTED\n";
print XINETD "  port                 = 1194\n";
print XINETD "  socket_type          = stream\n";
print XINETD "  protocol             = tcp\n";
print XINETD "  wait                 = no\n";
print XINETD "  bind                 = $xinetd\n";
print XINETD "  user                 = root\n";
print XINETD "  server               = $targetdir/scripts/tcp-wrapper.pl\n";
print XINETD "\}\n";
close(XINETD);

`ln -s /etc/surfnetids/xinetd.conf /etc/xinetd.d/surfids`;
#`mv $targetdir/xinetd.openvpn /etc/xinetd.d/openvpn`;
`/etc/init.d/xinetd restart`;

if (-e "/etc/surfnetids/openvpn.conf") {
    `mv /etc/surfnetids/openvpn.conf /etc/surfnetids/openvpn.conf-$ts`;
}

# Setting up openvpn config
open(OPENVPN, ">>/etc/surfnetids/openvpn.conf");
print OPENVPN "status $targetdir/log/openvpn-status.log\n";
print OPENVPN "up $targetdir/scripts/up.pl\n";
print OPENVPN "down $targetdir/scripts/down.pl\n";
print OPENVPN "ipchange $targetdir/scripts/ipchange.pl\n";
print OPENVPN "dh $targetdir/serverkeys/dh${key_size}.pem\n";
print OPENVPN "ca $targetdir/serverkeys/ca.crt\n";
print OPENVPN "cert $targetdir/serverkeys/tunserver.crt\n";
print OPENVPN "key $targetdir/serverkeys/tunserver.key\n";
close(OPENVPN);

# Restarting cron
`/etc/init.d/cron restart`;

# Setting up apache authentication
if (! -e "$targetdir/.htpasswd") {
    `htpasswd -b -c -m $targetdir/.htpasswd idssensor $htpasswd`;
}

# Checking the apache2 ports.conf file for the correct listening port (4443) 
if (-e "/etc/httpd/ports.conf") {
    $chk = `cat /etc/httpd/ports.conf | grep -v '^#.*\$' | grep 4443 | wc -l 2>/dev/null`; 
    chomp($chk); 
    if ($chk == 0) { 
        `echo "Listen $xinetd:4443" >> /etc/httpd/ports.conf 2>>$logfile`; 
    }
}

$ENV{"SURFIDS_COMMONNAME"} = "$hostname CA";
if (! -d "$ssldir") {
    `mkdir $ssldir`;
}

if (! -e "$ssldir/ca.key") {
    `openssl genrsa -out $ssldir/ca.key $key_size`;
    `openssl req -new -x509 -config $targetdir/tntools/selfsigned.cnf -days 365 -key $ssldir/ca.key -out $ssldir/ca.crt`;
}
$ENV{"SURFIDS_COMMONNAME"} = $hostname;
if (! -e "$ssldir/key.pem") {
    `openssl genrsa -out $ssldir/key.pem $key_size`;
    `openssl req -new -config $targetdir/tntools/selfsigned.cnf -key $ssldir/key.pem -out $ssldir/request.pem`;
    `openssl x509 -req -days 365 -in $ssldir/request.pem -CA $ssldir/ca.crt -CAkey $ssldir/ca.key -set_serial 01 -out $ssldir/cert.pem`;
    `openssl rsa -in $ssldir/key.pem -out $ssldir/key.pem.insecure`;
    `mv $ssldir/key.pem $ssldir/key.pem.secure`;
    `mv $ssldir/key.pem.insecure $ssldir/key.pem`;
}

`chmod +r $targetdir/serverkeys/ca.key`;

# RRD tool
if (! -d "/var/lib/rrd/") {
  `mkdir /var/lib/rrd/`;
}

$chk = `grep _unused_ /etc/iproute2/rt_tables | wc -l`;
chomp($chk);
if ($chk == 0) {
    my $ni = `tail -1 /etc/iproute2/rt_tables | awk '{print \$1}'`;
    chomp($ni);
    $ni++;
    if ($ni < 1001) {
        print "Setting up the iproute tables!\n";
        `echo "1000         _unused_" >> /etc/iproute2/rt_tables`;
    }
}

# Setting up reset_sensors_db.pl as init script and add to rc
`cp $targetdir/tntools/reset_sensors_db.pl /etc/init.d/surfids-reset-sensors 2>>$logfile`;
if (-e "/etc/init.d/postgresql-8.3") {
    `update-rc.d -f postgresql-8.3 remove 2>>$logfile`;
    `update-rc.d -f postgresql-8.3 defaults 18 21 2>>$logfile`;
}
`update-rc.d surfids-reset-sensors start 19 2 3 4 5 . 2>>$logfile`;

print "You will need to make sure the httpd daemon is listening on port 4443!\n";
