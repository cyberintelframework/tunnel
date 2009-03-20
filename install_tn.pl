#!/usr/bin/perl

####################################
# Tunnel installation script       #
# SURFids 2.10                     #
# Changeset 003                    #
# 16-12-2008                       #
# Jan van Lith & Kees Trippelvitz  #
####################################

#####################
# Changelog:
# 004 Fixed vars.conf generation
# 003 Renamed setmac.pl
# 002 Added tcp-wrapper.pl to xinetd
# 001 Initial release
#####################

##########################
# Variables
##########################

# Color codes
$n = "\033[0;39m";
$y = "\033[1;33m";
$r = "\033[1;31m";
$g = "\033[1;32m";

$targetdir = "/opt/surfnetids";
$configdir = "/etc/surfnetids";
$openvpn = "/usr/sbin/openvpn";
$ssldir = "/etc/apache2/surfidsssl";
$installdir = $0;
$installdir =~ s/install_tn.pl//g;
$logfile = "${installdir}install_tn.pl.log";
$itype = "install";

$subversion_group = "subversion";
$apache_user = "www-data";

$err = 0;

##########################
# Includes
##########################

require "functions_tn.pl";
$itype = "install";
##########################
# Main script
##########################

if (-e "./install_tn.pl.log") {
  `rm -f ./install_tn.pl.log 2>/dev/null`;
}

if (! -e "$configdir/") {
  `mkdir -p $configdir/ 2>>$logfile`;
  printmsg("Creating $configdir/:", $?);
  if ($? != 0) { $err++; }
}

if (! -e "$targetdir/") {
  `mkdir -p $targetdir/ 2>>$logfile`;
  printmsg("Creating $targetdir/:", $?);
  if ($? != 0) { $err++; }
}

if ( -e "$configdir/surfnetids-tn.conf") {
  $ts = time();
  `mv -f $configdir/surfnetids-tn.conf $configdir/surfnetids-tn.conf-$ts 2>>$logfile`;
  printmsg("Creating backup of surfnetids-tn.conf:", $?);
  if ($? != 0) { $err++; }
}

printdelay("Copying configuration file:");
`cp surfnetids-tn.conf $configdir/ 2>>$logfile`;
printresult($?);
if ($? != 0) { $err++; }

printdelay("Copying SURFnet IDS files:");
`cp -r ./* $targetdir/ 2>>$logfile`;
printresult($?);
if ($? != 0) { $err++; }
`rm $targetdir/surfnetids-tn.conf 2>>$logfile`;

if ($itype eq "install") {
  $confirm = "n";
  while ($confirm !~ /^(Y|y)$/) {
    # The key size
    $key_size = 0;
    while ($key_size !~ /^(1024|2048)$/) {
      $key_size = &prompt("Enter the key size [1024/2048]: ");
    }

    # The key country abbreviation (example: NL)
    $key_country = "none";
    $default = getcrtvalue("C");
    while ($key_country !~ /^[a-zA-Z]{2}$/) {
      $key_country = &prompt("Enter the country (2 character abbreviation) [$default]: ");
      if ($key_country eq "") {
        $key_country = $default;
      }
    }

    # The province or state you are located
    $key_prov = 0;
    $default = getcrtvalue("ST");
    while ($key_prov !~ /^[a-zA-Z ]*$/) {
      $key_prov = &prompt("Enter the province or state [$default]: ");
      chomp($key_prov);
      if ($key_prov eq "") {
        $key_prov = $default;
      }
    }

    # The city you are located
    $key_city = 0;
    $default = getcrtvalue("L");
    while ($key_city !~ /^[a-zA-Z ]*$/) {
      $key_city = &prompt("Enter the city [$default]: ");
      chomp($key_city);
      if ($key_city eq "") {
        $key_city = $default;
      }
    }

    # The organisation name
    $key_org = 0;
    $default = getcrtvalue("O");
    while ($key_org !~ /^[a-zA-Z ]*$/) {
      $key_org = &prompt("Enter the organisation [$default]: ");
      chomp($key_org);
      if ($key_org eq "") {
        $key_org = $default;
      }
    }

    # The province or state you are located
    $key_email = "none";
    $default = getcrtvalue("CN");
    while ($key_email !~ /^.{1,}@.{1,}\.[a-zA-Z]{2,4}$/) {
      $key_email = &prompt("Enter the admin email address [$default]: ");
      chomp($key_email);
      if ($key_email eq "") {
        $key_email = $default;
      }
    }
    printmsg("Key size", " $key_size ");
    printmsg("Country", $key_country);
    printmsg("Province", $key_prov);
    printmsg("City", $key_city);
    printmsg("Organisation name", $key_org);
    printmsg("Administrator email", $key_email);
    print "\n";
    $confirm = &prompt("Is this information correct? [y/n]: ");
  }

  `cp $targetdir/genkeys/vars.conf.dist $targetdir/genkeys/vars.conf`;

  open(VARS, ">$targetdir/genkeys/vars.conf");
  print VARS "\n";
  print VARS "\$key_config = \"\$genkeys/openssl.cnf\";\n";
  print VARS "\$key_dir = \"\$serverkeys\";\n";
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
}

print "\n";

####################
# Setting up hostname
####################

# Setting server hostname and configuring config files.
$check = 1;
while ($check eq 1) {
  $server = &prompt("Server hostname.domainname (FQDN) or IP (example: test.domain.nl): ");
  $check = 0;
  if ($server eq "") { $check = 1; }
  if ($server !~ /.*[A-Za-z].*/) {
    $check = validip($server);
  }
  if ($check != 1) {
    $confirm = "a";
    while ($confirm !~ /^(n|N|y|Y)$/) {
      printmsg("Server hostname/IP address:", "$server");
      $confirm = &prompt("Is this correct? [y/n]: ");
    }
    if ($confirm =~ /^(n|N)$/) {
      $check = 1;
    }
  }
}

print "\n";

####################
# Certificate generation
####################

printmsg("Generating new certificate config:", "info");

# Generating root certificate
if (! -e "$targetdir/serverkeys/ca.crt") {
  `$targetdir/genkeys/build-ca 2>>$logfile`;
  printmsg("Generating root certificate:", $?);
  if ($? != 0) { $err++; }
} else {
  printmsg("Root certificate already exists:", "info");
}

# Generating server certificate
if (! -e "$targetdir/serverkeys/tunserver.crt") {
  $ENV{"KEY_COMMONNAME"} = "$server";
  $ENV{"KEY_CERTTYPE"} = "server";

  printdelay("Generating server certificate:");
  `$targetdir/genkeys/build-key-server tunserver 2>>$logfile`;
  printresult($?);
  if ($? != 0) { $err++; }
} else {
  printmsg("Server certificate already exists:", "info");
}

# Generate Diffie-Hellman parameters
if (! -e "$targetdir/serverkeys/dh${key_size}.pem") {
  printmsg("Generating DH parameters. This could take a few minutes:", "info");
  `$targetdir/genkeys/build-dh`;
  printmsg("Generating Diffie-Hellman parameters:", $?);
  if ($? != 0) { $err++; }
} else {
  printmsg("Diffie-Hellman parameters already exist:", "info");
}

####################
# Setting up dhclient3
####################

if ( -e "/etc/dhcp3/dhclient.conf") {
  $ts = time();
  `mv -f /etc/dhcp3/dhclient.conf /etc/dhcp3/dhclient.conf-$ts 2>>$logfile`;
  printmsg("Creating backup of dhclient.conf:", $?);
  if ($? != 0) { $err++; }
}

`mv -f $targetdir/dhclient.conf /etc/dhcp3/ 2>>$logfile`;
printmsg("Installing new dhclient.conf:", $?);
if ($? != 0) { $err++; }

print "\n";

####################
# Setting up xinetd
####################

# The IP address where xinetd will be listening on for OpenVPN connections
$xinetd = 0;
$validip = 1;
while ($validip != 0) {
  $validip = validip($server);
  if ($validip == 0) {
    $xinetd = &prompt("Enter the IP listener address for xinetd [$server]: ");
  } else {
    $xinetd = &prompt("Enter the IP listener address for xinetd: ");
  }
  if ($xinetd eq "") {
    $xinetd = $server;
  }
  $validip = validip($xinetd);
}

if ( -e "/etc/xinetd.d/openvpn") {
  $ts = time();
  `mv -f /etc/xinetd.d/openvpn /etc/openvpn/xinetd.openvpn-$ts 2>>$logfile`;
  printmsg("Creating backup xinetd openvpn config:", $?);
  if ($? != 0) { $err++; }
}

open(XINETD, ">$targetdir/xinetd.openvpn");
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
#print XINETD "  server_args          = --config /etc/openvpn/server.conf\n";
print XINETD "\}\n";
close(XINETD);

`mv $targetdir/xinetd.openvpn /etc/xinetd.d/openvpn 2>>$logfile`;
printmsg("Creating new xinetd openvpn config:", $?);
if ($? != 0) { $err++; }

if ($itype eq "upgrade") {
  $key_size = `ls $targetdir/serverkeys/ | grep dh | grep pem`;
  chomp($key_size);
  $key_size =~ s/dh//g;
  $key_size =~ s/\.pem//g;
  if ("$key_size" eq "") {
    $key_size = 1024;
  }
}

open(OPENVPN, ">>$targetdir/openvpn-server.conf");
print OPENVPN "status $targetdir/log/openvpn-status.log\n";
print OPENVPN "up $targetdir/scripts/up.pl\n";
print OPENVPN "down $targetdir/scripts/down.pl\n";
print OPENVPN "ipchange $targetdir/scripts/ipchange.pl\n";
print OPENVPN "dh $targetdir/serverkeys/dh${key_size}.pem\n";
print OPENVPN "ca $targetdir/serverkeys/ca.crt\n";
print OPENVPN "cert $targetdir/serverkeys/tunserver.crt\n";
print OPENVPN "key $targetdir/serverkeys/tunserver.key\n";
close(OPENVPN);

####################
# Setting up OpenVPN
####################

if ( -e "/etc/openvpn/server.conf") {
  $ts = time();
  `mv -f /etc/openvpn/server.conf /etc/openvpn/server.conf-$ts 2>>$logfile`;
  printmsg("Creating backup of server.conf:", $?);
  if ($? != 0) { $err++; }
}

`mv $targetdir/openvpn-server.conf /etc/openvpn/server.conf 2>>$logfile`;
printmsg("Creating new openvpn server config:", $?);
if ($? != 0) { $err++; }

if (! -d "/dev/net/") {
  `mkdir -f /dev/net/ 2>>$logfile`;
  printmsg("Creating /dev/net:", $?);
  if ($? != 0) { $err++; }
}

if (! -e "/dev/net/tun") {
  `mknod /dev/net/tun c 10 200 2>>$logfile`;
  printmsg("Creating /dev/net/tun:", $?);
  if ($? != 0) { $err++; }
}

####################
# Setting up crontab
####################

open(CRONTAB, ">> /etc/crontab");
open(CRONLOG, "crontab.tn");
while (<CRONLOG>) {
  $line = $_;
  chomp($line);
  if ($line ne "") {
    @ar_line = split(/ /, $line);
    $check = $ar_line[6];
    chomp($check);
    $file = `cat crontab.tn | grep -F "$line" | awk '{print \$7}' | awk -F"/" '{print \$NF}' 2>>$logfile`;
    chomp($file);
    $chk = checkcron($file);
    if ($chk == 0) {
      printmsg("Adding crontab rule for $file:", "info");
      print CRONTAB $line ."\n";
    }
  }
}
close(CRONTAB);
close(CRONLOG);

printdelay("Restarting cron:");
`/etc/init.d/cron restart 2>>$logfile`;
printresult($?);
if ($? != 0) { $err++; }

####################
# Setting up Apache
####################

print "\n";

$apachev = "apache2";
$apachedir = "/etc/$apachev/sites-enabled";
$apachesiteadir = "/etc/$apachev/sites-available/";

#if ($itype eq "install") {
  while (! -d $apachedir) {
    printmsg("Could not find the $apachev config dir. Is $apachev installed?", "warning");
    $apachedir = &prompt("Location of the $apachev config dir [q to quit installation]: ");
    if ($apachedir eq "q") {
      exit;
    }
    if (! -d $apachedir) {
      printmsg("Checking for $apachedir:", "false");
    }
  }

  if ( -e "$apachesiteadir/surfnetids-tn-apache.conf") {
    $ts = time();
    `mv -f $apachesiteadir/surfnetids-tn-apache.conf $targetdir/surfnetids-tn-apache.conf-$ts 2>>$logfile`;
    printmsg("Creating backup of surfnetids-tn-apache.conf:", $?);
    if ($? != 0) { $err++; }
  }

  `cp $targetdir/surfnetids-tn-apache.conf $apachesiteadir 2>>$logfile`;
  printmsg("Setting up $apachev configuration:", $?);
  if ($? != 0) { $err++; }

  printdelay("Activating SURFids tunnel server scripts:");
  `a2ensite surfnetids-tn-apache.conf 2>>$logfile`;
  printresult($?);
  if ($? != 0) { $err++; }
#}

if (! -e "$targetdir/.htpasswd") {
  $er = 1;
  while ($er != 0) {
    printmsg("Starting http access configuration:", "info");
    `htpasswd -c -m $targetdir/.htpasswd idssensor 2>>$logfile`;
    printmsg("Setting up http access:", $?);
    $er = $?;
    if ($? != 0) { $err++; }
  }
}

#printdelay("Restarting the $apachev server:");
#`/etc/init.d/$apachev restart 2>>$logfile`;
#printresult($?);
#if ($? != 0) { $err++; }

print "\n";

if (-e "/etc/apache2/ssl/") {
  printdelay("Moving SSL certificates to new SSL dir:");
  `cp /etc/apache2/ssl/* $ssldir 2>>$logfile`;
  printresult($?);
}

if (! -e "$ssldir/ca.crt") {
  print "\n";
  print "-------------------------------------------------------------------------------------------------\n";
  print "The Tunnel server needs to run an apache2 with a SSL certificate. We can create a \n";
  print "self-signed one right now, but the preferred method is ofcourse getting a valid certificate \n";
  print "signed by a trusted certificate authority.\n";
  print "Don't worry about any mistakes made within this process, you will have the option to redo it again\n";
  print "at the end.\n";
  print "-------------------------------------------------------------------------------------------------\n";
  print "\n";

  $confirm = "none";
  while ($confirm !~ /^(n|N|y|Y)$/) {
    $confirm = &prompt("Do you want to generate a self-signed certificate? [Y/n]: ");
  }
  if ($confirm =~ /^(y|Y)$/) {
    $confirm = "y";
    while ($confirm =~ /^(y|Y)$/) {
      print "\n";
      if (! -d "$ssldir") {
        printdelay("Creating apache2 ssl directory:");
        `mkdir $ssldir 2>>$logfile`;
        printresult($?);
      }

      if (! -e "$ssldir/ca.key") {
        print "##########################################\n";
        print "########## Generating ROOT CA ############\n";
        print "##########################################\n";
        printmsg("Generating root CA certificate key:", "info");
        `openssl genrsa -des3 -out $ssldir/ca.key $key_size`;
        if ($? != 0) { $err++; }

        print "\n";
        printmsg("Generating root CA certificate:", "info");
        print "${r}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${n}\n";
        printmsg("    The Common Name should be:", "$server CA");
        print "${r}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${n}\n";
        `openssl req -new -x509 -days 365 -key $ssldir/ca.key -out $ssldir/ca.crt`;
        if ($? != 0) { $err++; }
      } else {
        print "$ssldir/ca.key already exists!\n";
      }

      if (! -e "$ssldir/key.pem") {
        print "\n";
        print "##########################################\n";
        print "######## Generating Server Certs #########\n";
        print "##########################################\n";
        printmsg("Generating server key:", "info");
        `openssl genrsa -des3 -out $ssldir/key.pem $key_size`;
        if ($? != 0) { $err++; }

        print "\n";
        printmsg("Generating signing request:", "info");
        print "${r}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${n}\n";
        printmsg("    The Common Name should be:", "$server");
        print "${r}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${n}\n";
        `openssl req -new -key $ssldir/key.pem -out $ssldir/request.pem`;
        if ($? != 0) { $err++; }

        print "\n";
        printmsg("Generating server certificate:", "info");
        `openssl x509 -req -days 365 -in $ssldir/request.pem -CA $ssldir/ca.crt -CAkey $ssldir/ca.key -set_serial 01 -out $ssldir/cert.pem`;
        if ($? != 0) { $err++; }

        $ec = 0;
        printmsg("Finishing certificate generation:", "info");
        `openssl rsa -in $ssldir/key.pem -out $ssldir/key.pem.insecure 2>>$logfile`;
        if ($? != 0) { $ec++; }
        `mv $ssldir/key.pem $ssldir/key.pem.secure 2>>$logfile`;
        if ($? != 0) { $ec++; }
        `mv $ssldir/key.pem.insecure $ssldir/key.pem 2>>$logfile`;
        if ($? != 0) { $ec++; }
        if ($ec != 0) { $err++; }
        $ec = 0;
      } else {
        print "$ssldir/key.pem already exists!\n";
      }

      print "\n";
      print "-------------------------------------------------------------------------------------------------\n";
      print "You now have the option to redo the certificate generation process if you have made any mistakes.\n";
      print "This will remove any certificates present in the $ssldir!\n";
      print "-------------------------------------------------------------------------------------------------\n";
      print "\n";

      $confirm = &prompt("Do you want to regenerate a self-signed certificate? [y/N]: ");
      if ($confirm =~ /^(y|Y)$/) {
        $ts = time();
        `rm $ssldir/* 2>>$logfile`;
        if ($? != 0) { $err++; }
        `rm $targetdir/updates/CAcert.pem 2>>$logfile`;
        if ($? != 0) { $err++; }
      }
      print "\n";
    }

    printdelay("Enabling SSL for $apachev:");
    `a2enmod ssl 2>>$logfile`;
    printresult($?);
    if ($? != 0) { $err++; }
  }
}

printdelay("Restarting the $apachev server:");
`/etc/init.d/$apachev restart 2>>$logfile`;
printresult($?);
if ($? != 0) { $err++; }

print "\n";

####################
# Setting up certificate permissions
####################

$ec = 0;
`chmod 777 $targetdir/clientkeys/ 2>>$logfile`;
if ($? != 0) { $ec++; }
`chmod 777 $targetdir/serverkeys/ 2>>$logfile`;
if ($? != 0) { $ec++; }
`chmod +r $targetdir/serverkeys/ca.key 2>>$logfile`;
if ($? != 0) { $ec++; }
printmsg("Setting up permissions:", $ec);
if ($ec != 0) { $err++; }
$ec = 0;

####################
# IPVS support
####################

$confirm = "a";

while ($confirm !~ /^(y|Y|n|N)$/) {
  $confirm = &prompt("Do you want to enable IPVS support? [y/n]: ");
  if ($confirm !~ /^(n|N)$/) {
    `ipvsadm --help 2>/dev/null`;
    if ($? != 0) {
      printmsg("IPVS software possibly not installed:", "info");
      print "\n";
      print "-------------------------------------------------------------------------------------------------\n";
      print "            Install IP Virtual Server daemon. (Needed for Multi-honeypot support)\n";
      print "The ipvsadm daemon needs to be installed and the kernel needs to be patched. Check ids.surfnet.nl\n";
      print "You can still enable IPVS support and do the patching an installing of the daemon later.\n";
      print "-------------------------------------------------------------------------------------------------\n";
      print "\n";
      $confirm = &prompt("Still want to enable IPVS support? [y/n]: ");
    }
  }
}

$ipvasadm = 0;
if ($confirm =~ /^(y|Y)$/) {
  `cp $targetdir/scripts/iptables.ipvs /etc/init.d/ 2>>$logfile`;
  printmsg("Installing SURFids IPVS files:", $?);
  if ($? != 0) { $err++; }
  `update-rc.d iptables.ipvs start 01 2 3 4 5 . 2>>$logfile`;
  printmsg("Adding iptable rules to boot sequence:", $?);
  if ($? != 0) { $err++; }
  $ipvsadm = 1;
}

####################
# RRDtool
####################
if (! -d "/var/lib/rrd/") {
  printdelay("Creating /var/lib/rrd/:");
  `mkdir /var/lib/rrd/ 2>>$logfile`;
  printresult($?);
}

####################
# Removing obsolete files
####################
if (-e "$targetdir/tunnel_remove.txt") {
  @list = `cat $targetdir/tunnel_remove.txt`;
  foreach $tar (@list) {
    chomp($tar);
    if ("$tar" ne "") {
      if ($tar !~ /.*\.\..*/) {
        if (-e "$targetdir/$tar") {
          printmsg("Removing $tar:", "info");
        }
      }
    }
  }
}

####################
# Cleaning up
####################

$ec = 0;
`rm -f $targetdir/crontab.tn 2>/dev/null`;
if ($? != 0) { $ec++; }
`rm -f $targetdir/surfnetids-tn-apache.conf 2>/dev/null`;
if ($? != 0) { $ec++; }
`rm -f $targetdir/openvpn-server.conf 2>/dev/null`;
if ($? != 0) { $ec++; }
`rm -f $targetdir/install_tn.pl 2>/dev/null`;
if ($? != 0) { $ec++; }
`rm -f $targetdir/functions_tn.pl 2>/dev/null`;
if ($? != 0) { $ec++; }
`rm -f $targetdir/install_tn.pl.log 2>/dev/null`;
if ($? != 0) { $ec++; }
`rm -f $targetdir/tunnel_remove.txt 2>/dev/null`;
if ($? != 0) { $ec++; }
printmsg("Cleaning up the temporary files:", $ec);
$ec = 0;
rmsvn($targetdir);

print "\n";
if ($err > 0) {
  print "[${r}Warning${n}] $err error(s) occurred while installing. Check out the logfile 'install_tn.pl.log'.\n";
  print "\n";
}

print "#####################################\n";
print "# ${g}SURFnet IDS installation complete${n} #\n";
print "#####################################\n";
print "\n";
print "For extra security keep the scripts key (/opt/surfnetids/scriptkeys/scripts.key) somewhere safe (offline).\n";
print "\n";
print "Interesting configuration files:\n";
print "  ${g}/etc/crontab\n";
print "  $targetdir/updates/client.conf${n}\n";

print "Still needs configuration:\n";
print "  ${g}$configdir/surfnetids-tn.conf\n";
print "  $targetdir/updates/sensor.conf\n";
print "  $targetdir/updates/wgetrc${n}\n";
if ($ipvsadm == 1) {
  print "  ${g}/etc/init.d/iptables.ipvs${n}\n";
}
print "\n";
print "NOTICE: You will have to add the sensor scripts manually to your SVN repository!\n";
print "NOTICE: Also install the logging server part of the SURFnet IDS system!\n";
print "\n";
print "For more information go to http://ids.surfnet.nl/\n";
