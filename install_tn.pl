#!/usr/bin/perl

####################################
# Tunnel installation script       #
# SURFids 2.10                     #
# Changeset 004                    #
# 04-03-2009                       #
# Jan van Lith & Kees Trippelvitz  #
####################################

#####################
# Changelog:
# 004 Removed the SVN stuff
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

##########################
# Dependency checks
##########################

if (! -e "/etc/xinetd.d/") {
  printmsg("Checking for xinetd.d:", "false");
}

if (! -e "/etc/dhcp3/") {
  printmsg("Checking for dhclient3:", "false");
}

if (-e "$targetdir/server/") {
  printmsg("SURFnet IDS tunnel server already installed:", "info");
  $itype = "none";
  while ($itype !~ /^(upgrade|install|exit)$/) {
    $itype = &prompt("Do you want to upgrade or do a complete new installation? [upgrade/install/exit]: ");
  }
  if ($itype =~ /^(exit)$/) {
    exit;
  } elsif ($itype =~ /^(install)$/) {
    printmsg("Cleaning up old files:", "info");
    `$installdir/tntools/uninstall.pl 1 2>>$logfile`;
  } elsif ($itype =~ /^(upgrade)$/) {
    if (-e "$targetdir/genkeys/vars.conf") {
      $ts = time();
      `cp $targetdir/genkeys/vars.conf $targetdir/genkeys/vars.conf-$ts 2>>$logfile`;
    }
  } else {
    print "Unkown error!\n";
    exit;
  }
}

if (-e "./install_tn.pl.log") {
  `rm -f ./install_tn.pl.log 2>/dev/null`;
}

##########################
# Main script
##########################

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

  open(VARS, ">$targetdir/genkeys/vars.conf");
  print VARS "D=$targetdir\n";
  print VARS "genkeys=\$D/genkeys\n";
  print VARS "serverkeys=\$D/serverkeys\n";
  print VARS "clientkeys=\$D/clientkeys\n";
  print VARS "\n";
  print VARS "export D=$targetdir\n";
  print VARS "export KEY_CONFIG=\$genkeys/openssl.cnf\n";
  print VARS "export KEY_DIR=\$serverkeys\n";
  print VARS "export KEY_SIZE=\"$key_size\"\n";
  print VARS "export KEY_COUNTRY=\"$key_country\"\n";
  print VARS "export KEY_PROVINCE=\"$key_prov\"\n";
  print VARS "export KEY_CITY=\"$key_city\"\n";
  print VARS "export KEY_ORG=\"$key_org\"\n";
  print VARS "export KEY_EMAIL=\"$key_email\"\n";
  print VARS "export KEY_UNITNAME=\"SURFnet IDS\"\n";
  print VARS "export KEY_COMMONNAME=\"server\"\n";
  print VARS "export KEY_CERTTYPE=\"client\"\n";
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

# Generate script certificate
if (! -e "$targetdir/updates/scripts.crt") {
  $ec = 0;
  $ENV{"KEY_DIR"} = "$targetdir/updates/";
  $ENV{"KEY_COMMONNAME"} = "scripts";
  $ENV{"KEY_CERTTYPE"} = "objsign";

  `$targetdir/genkeys/build-ca 2>>$logfile`;
  if ($? != 0) { $ec++; }
  `mv $targetdir/updates/ca.key $targetdir/scriptkeys/scripts.key 2>>$logfile`;
  if ($? != 0) { $ec++; }
  `mv $targetdir/updates/ca.crt $targetdir/updates/scripts.crt 2>>$logfile`;
  if ($? != 0) { $ec++; }
  if ($ec != 0) { $err++; }
  printmsg("Generating scripts certificate:", $ec);
  $ec = 0;
} else {
  printmsg("Scripts certificate already exists:", "info");
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

print "\n";

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
# Setting up iproute2
####################

if (-e "/etc/iproute2/rt_tables") {
  if (-w "/etc/iproute2/rt_tables") {
    $iprcheck = `cat /etc/iproute2/rt_tables | wc -l 2>>$logfile`;
    chomp($iprcheck);
    if ($? != 0) { $err++; }
    if ($iprcheck > 200) {
      printmsg("No need to modify /etc/iproute2/rt_tables:", "info");
    } else {
      $ts = time();
      `cp /etc/iproute2/rt_tables /etc/iproute2/rt_tables.old-$ts 2>>$logfile`;
      printmsg("Creating backup of rt_tables:", $?);
      if ($? != 0) { $err++; }

      open(RT, ">>/etc/iproute2/rt_tables");
      $n = 0;
      for ($i=20; $i<221; $i++) {
        print RT "$i              tap$n\n";
        $n++;
      }
    }
  } else {
    printmsg("Setting up iproute2 tables:", 1);
  }
} else {
  printmsg("Setting up iproute2 tables:", 2);
}

####################
# Setting up sensor config
####################

$ec = 0;
`sed 's/^remote.*\$/remote $server/' ./updates/client.conf > $targetdir/updates/client.conf 2>>$logfile`;
if ($? != 0) { $ec = 1; }
`cp $targetdir/updates/client.conf ./updates/client.conf 2>>$logfile`;
if ($? != 0) { $ec = 2; }
`sed 's/^tls-remote.*\$/tls-remote $server/' ./updates/client.conf > $targetdir/updates/client.conf 2>>$logfile`;
if ($? != 0) { $ec = 3; }
printmsg("Configuring client.conf:", $ec);
if ($ec != 0) { $err++; }
$ec = 0;

$ec = 0;
`sed 's/^remote.*\$/remote $server/' ./updates/client.conf.temp > $targetdir/updates/client.conf.temp 2>>$logfile`;
if ($? != 0) { $ec = 1; }
`cp $targetdir/updates/client.conf.temp ./updates/client.conf.temp 2>>$logfile`;
if ($? != 0) { $ec = 2; }
`sed 's/^tls-remote.*\$/tls-remote $server/' ./updates/client.conf.temp > $targetdir/updates/client.conf.temp 2>>$logfile`;
if ($? != 0) { $ec = 3; }
printmsg("Configuring client.conf.temp:", $ec);
if ($ec != 0) { $err++; }
$ec = 0;

printdelay("Configuring sensor.conf:");
`sed 's/^\\\$server = \"enter_server_here\";\$/\\\$server = \"$server\";/' ./updates/sensor.conf > $targetdir/updates/sensor.conf 2>>$logfile`;
printresult($?);
if ($? != 0) { $err++; }

open(SERVERVARS, ">>$targetdir/genkeys/servervars");
print SERVERVARS "export KEY_COMMONNAME=\"$server\"\n";
close(SERVERVARS);
$chk = `cat $targetdir/genkeys/servervars | grep -i $server | wc -l 2>>$logfile`;
chomp($chk);
if ($? != 0) { $err++; }
if ($chk == 0) {
  printmsg("Configuring servervars:", "false");
} else {
  printmsg("Configuring servervars:", 0);
}

`$targetdir/tntools/makeversion.pl >/dev/null 2>>$logfile`;
printmsg("Signing sensor scripts:", $?);
if ($? != 0) { $err++; }

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
