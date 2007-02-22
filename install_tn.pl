#!/usr/bin/perl

###################################
# Tunnel installation script      #
# SURFnet IDS                     #
# Version 1.04.01                 #
# 05-02-2007                      #
# Jan van Lith & Kees Trippelvitz #
###################################

#####################
# Changelog:
# 1.04.01 Initial release
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
  $confirm = "none";
  while ($confirm !~ /^(n|N|y|Y)$/) {
    $confirm = &prompt("Overwrite old installation? [y/n]: ");
  }
  if ($confirm =~ /^(n|N)$/) {
    exit;
  }
}

print "${y}Also install the 1.04-package-log part of the SURFnet IDS system.\n${n}";

##########################
# Main script
##########################

if (! -e "$configdir/") {
  `mkdir -p $configdir/`;
  printmsg("Creating $configdir/:", $?);
}

if (! -e "$targetdir/") {
  `mkdir -p $targetdir/`;
  printmsg("Creating $targetdir/:", $?);
}

if ( -e "$configdir/surfnetids-tn.conf") {
  $ts = time();
  `mv -f $configdir/surfnetids-tn.conf $configdir/surfnetids-tn.conf-$ts`;
  printmsg("Creating backup of surfnetids-tn.conf:", $?);
}

`cp surfnetids-tn.conf $configdir/`;
printmsg("Copying configuration file:", $?);

`cp -r ./* $targetdir/`;
printmsg("Copying surfnetids files:", $?);
`rm $targetdir/surfnetids-tn.conf`;

$confirm = "n";
while ($confirm !~ /^(Y|y)$/) {
  # The key size
  $key_size = 0;
  while ($key_size !~ /^(1024|2048)$/) {
    $key_size = &prompt("Enter the key size [1024/2048]: ");
  }

  # The key country abbreviation (example: NL)
  $key_country = "none";
  while ($key_country !~ /^[a-zA-Z]{2}$/) {
    $key_country = &prompt("Enter the country (2 character abbreviation): ");
  }

  # The province or state you are located
  $key_prov = 0;
  while ($key_prov !~ /^[a-zA-Z ]*$/) {
    $key_prov = &prompt("Enter the province or state: ");
    chomp($key_prov);
    if ($key_prov eq "") {
      $key_prov = 0;
    }
  }

  # The city you are located
  $key_city = 0;
  while ($key_city !~ /^[a-zA-Z ]*$/) {
    $key_city = &prompt("Enter the city: ");
    chomp($key_city);
    if ($key_city eq "") {
      $key_city = 0;
    }
  }

  # The organisation name
  $key_org = 0;
  while ($key_org !~ /^[a-zA-Z ]*$/) {
    $key_org = &prompt("Enter the organisation: ");
    chomp($key_org);
    if ($key_org eq "") {
      $key_org = 0;
    }
  }

  # The province or state you are located
  $key_email = "none";
  while ($key_email !~ /^.{1,}@.{1,}\.[a-zA-Z]{2,4}$/) {
    $key_email = &prompt("Enter the admin email address: ");
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

print "\n";

####################
# Setting up hostname
####################

# Setting server hostname and configuring config files.
$check = 1;
while ($check eq 1) {
  $server = &prompt("Server hostname.domainname or IP (example: test.domain.nl): ");
  $check = 0;
  if ($server eq "") { $check = 1; }
  if ($server !~ /.*[AZaz].*/) {
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
  `$targetdir/genkeys/build-ca 2>/dev/null`;
  printmsg("Generating root certificate:", $?);
} else {
  printmsg("Root certificate already exists:", "info");
}

# Generating server certificate
if (! -e "$targetdir/serverkeys/tunserver.crt") {
  $ENV{"KEY_COMMONNAME"} = "$server";
  $ENV{"KEY_CERTTYPE"} = "server";

  `$targetdir/genkeys/build-key-server tunserver 2>/dev/null`;
  printmsg("Generating server certificate:", $?);
} else {
  printmsg("Server certificate already exists:", "info");
}

# Generate Diffie-Hellman parameters
if (! -e "$targetdir/serverkeys/dh${key_size}.pem") {
  printmsg("Generating DH parameters. This could take a few minutes:", "info");
  `$targetdir/genkeys/build-dh`;
  printmsg("Generating Diffie-Hellman parameters:", $?);
  if ($? != 0) { push(@errors, "3"); }
} else {
  printmsg("Diffie-Hellman parameters already exist:", "info");
}

# Generate script certificate
if (! -e "$targetdir/updates/scripts.crt") {
  $ec = 0;
  $ENV{"KEY_DIR"} = "$targetdir/updates/";
  $ENV{"KEY_COMMONNAME"} = "scripts";
  $ENV{"KEY_CERTTYPE"} = "objsign";

  `$targetdir/genkeys/build-ca 2>/dev/null`;
  if ($? != 0) { $ec++; }
  `mv $targetdir/updates/ca.key $targetdir/scriptkeys/scripts.key`;
  if ($? != 0) { $ec++; }
  `mv $targetdir/updates/ca.crt $targetdir/updates/scripts.crt`;
  if ($? != 0) { $ec++; }
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
  `mv -f /etc/dhcp3/dhclient.conf /etc/dhcp3/dhclient.conf-$ts`;
  printmsg("Creating backup of dhclient.conf:", $?);
}

`mv -f $targetdir/dhclient.conf /etc/dhcp3/`;
printmsg("Installing new dhclient.conf:", $?);

print "\n";

####################
# Setting up xinetd
####################

# The IP address where xinetd will be listening on for OpenVPN connections
$xinetd = 0;
$validip = 1;
while ($validip != 0) {
  $xinetd = &prompt("Enter the IP listener address for xinetd [$server]: ");
  if ($xinetd eq "") {
    $xinetd = $server;
  }
  $validip = validip($xinetd);
}

if ( -e "/etc/xinetd.d/openvpn") {
  $ts = time();
  `mv -f /etc/xinetd.d/openvpn /etc/openvpn/xinetd.openvpn-$ts`;
  printmsg("Creating backup xinetd openvpn config:", $?);
}

print "\n";

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
print XINETD "  server               = $openvpn\n";
print XINETD "  server_args          = --config /etc/openvpn/server.conf\n";
print XINETD "\}\n";
close(XINETD);

`mv $targetdir/xinetd.openvpn /etc/xinetd.d/openvpn`;
printmsg("Creating new xinetd openvpn config:", $?);

open(OPENVPN, ">>$targetdir/openvpn-server.conf");
print OPENVPN "status $targetdir/log/openvpn-status.log\n";
print OPENVPN "up $targetdir/scripts/up.pl\n";
print OPENVPN "down $targetdir/scripts/down.pl\n";
print OPENVPN "ipchange $targetdir/scripts/setmac.pl\n";
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
  `mv -f /etc/openvpn/server.conf /etc/openvpn/server.conf-$ts`;
  printmsg("Creating backup of server.conf:", $?);
}

`mv $targetdir/openvpn-server.conf /etc/openvpn/server.conf`;
printmsg("Creating new openvpn server config:", $?);

if (! -d "/dev/net/") {
  `mkdir -f /dev/net/`;
  printmsg("Creating /dev/net:", $?);
}

if (! -e "/dev/net/tun") {
  `mknod /dev/net/tun c 10 200`;
  printmsg("Creating /dev/net/tun:", $?);
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
    $file = `cat crontab.tn | grep -F "$line" | awk '{print \$7}' | awk -F"/" '{print \$NF}'`;
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
`/etc/init.d/cron restart`;
printresult($?);

####################
# Setting up Apache
####################

print "\n";

$apachev = "";
while ($apachev !~ /^(apache|apache2|apache-ssl)$/) {
  $apachev = &prompt("Which apache are you using [apache/apache2/apache-ssl]?: ");
  if (! -e "/etc/$apachev/") {
    printmsg("Checking for $apachev:", "false");
    $confirm = "a";
    while ($confirm !~ /^(n|N|y|Y)$/) {
      printmsg("Apache server:", "$apachev");
      $confirm = &prompt("Is this correct? [y/n]: ");
    }
    if ($confirm =~ /^(n|N)$/) {
      $apachev = "none";
    }
  }
}

if ($apachev eq "apache2") {
  $apachedir = "/etc/$apachev/sites-enabled/";
} else {
  $apachedir = "/etc/$apachev/conf.d/";
}

while (! -d $apachedir) {
  $apachedir = &prompt("Location of the $apachev config dir: ");
  if (! -d $apachedir) {
    printmsg("Checking for $apachedir:", "false");
  }
}

if ( -e "$apachedir/surfnetids-tn-apache.conf") {
  $ts = time();
  `mv -f $apachedir/surfnetids-tn-apache.conf $apachedir/surfnetids-tn-apache.conf-$ts`;
  printmsg("Creating backup of surfnetids-tn-apache.conf:", $?);
}

`cp $targetdir/surfnetids-tn-apache.conf $apachedir`;
printmsg("Setting up $apachev configuration:", $?);

if (! -e "$targetdir/.htpasswd") {
  $err = 1;
  while ($err != 0) {
    printmsg("Starting http access configuration:", "info");
    `htpasswd -c -m $targetdir/.htpasswd idssensor`;
    printmsg("Setting up http access:", $?);
    $err = $?;
  }
}

printdelay("Restarting the $apachev server:");
`/etc/init.d/$apachev restart 2>/dev/null`;
printresult($?);

####################
# Setting up certificate permissions
####################

$ec = 0;
`chmod 777 $targetdir/clientkeys/`;
if ($? != 0) { $ec++; }
`chmod 777 $targetdir/serverkeys/`;
if ($? != 0) { $ec++; }
`chmod +r $targetdir/serverkeys/ca.key`;
if ($? != 0) { $ec++; }
printmsg("Setting up permissions:", $ec);
$ec = 0;

####################
# Setting up iproute2
####################

if (-e "/etc/iproute2/rt_tables") {
  if (-w "/etc/iproute2/rt_tables") {
    $iprcheck = `cat /etc/iproute2/rt_tables | wc -l`;
    chomp($iprcheck);
    if ($iprcheck > 200) {
      printmsg("No need to modify /etc/iproute2/rt_tables:", "info");
    } else {
      $ts = time();
      `cp /etc/iproute2/rt_tables /etc/iproute2/rt_tables.old-$ts`;
      printmsg("Creating backup of rt_tables:", $?);
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
`sed 's/^remote.*\$/remote $server/' ./updates/client.conf > $targetdir/updates/client.conf`;
if ($? != 0) { $ec = 1; }
`cp $targetdir/updates/client.conf ./updates/client.conf`;
if ($? != 0) { $ec = 2; }
`sed 's/^tls-remote.*\$/tls-remote $server/' ./updates/client.conf > $targetdir/updates/client.conf`;
if ($? != 0) { $ec = 3; }
printmsg("Configuring client.conf:", $ec);
$ec = 0;

`sed 's/^server=\"enter_server_name\"\$/server=\"$server\"/' ./updates/sensor.conf > $targetdir/updates/sensor.conf`;
printmsg("Configuring sensor.conf:", $?);

open(SERVERVARS, ">>$targetdir/genkeys/servervars");
print SERVERVARS "export KEY_COMMONNAME=\"$server\"\n";
close(SERVERVARS);
$chk = `cat $targetdir/genkeys/servervars | grep -i $server | wc -l`;
chomp($chk);
if ($chk == 0) {
  printmsg("Configuring servervars:", "false");
} else {
  printmsg("Configuring servervars:", 0);
}

`$targetdir/scripts/makeversion.pl >/dev/null`;
printmsg("Signing sensor scripts:", $?);

####################
# IPVS support
####################

$confirm = "a";

while ($confirm !~ /^(y|Y|n|N)$/) {
  $confirm = &prompt("Do you want to enable IPVS support? [y/n]: ");
  if ($confirm !~ /^(n|N)$/) {
    `ipvsadm --help`;
    if ($? != 0) {
      printmsg("IPVS software possibly not installed:", "info");
      $confirm = &prompt("Still want to enable IPVS support? [y/n]: ");
    }
  }
}

if ($confirm =~ /^(y|Y)$/) {
  `cp $targetdir/scripts/iptables.ipvs /etc/init.d/`;
  printmsg("Installing SURF IDS IPVS files:", $?);
  `update-rc.d iptables.ipvs start 01 2 3 4 5 .`;
  printmsg("Adding iptable rules to boot sequence:", $?);
}

####################
# Cleaning up
####################

$ec = 0;
`rm -f $targetdir/crontab.tn`;
if ($? != 0) { $ec++; }
`rm -f $targetdir/surfnetids-tn-apache.conf`;
if ($? != 0) { $ec++; }
`rm -f $targetdir/openvpn-server.conf`;
if ($? != 0) { $ec++; }
`rm -f $targetdir/install_tn.pl`;
if ($? != 0) { $ec++; }
`rm -f $targetdir/functions_tn.pl`;
if ($? != 0) { $ec++; }
printmsg("Cleaning up the temporary files:", $ec);
$ec = 0;

print "#####################################\n";
print "# ${g}SURFnet IDS installation complete${n} #\n";
print "#####################################\n";
print "\n";
print "For extra security keep the scripts key (/opt/surfnetids/scriptkeys/scripts.key) somewhere safe (offline).\n";
print "\n";
print "Interesting configuration files:\n";
print "  ${g}/etc/crontab\n";
print "  $targetdir/updates/client.conf\n";
print "  $targetdir/updates/sensor.conf${n}\n";

print "Still needs configuration:\n";
print "  ${g}$configdir/surfnetids-tn.conf\n";
print "  $targetdir/updates/wgetrc${n}\n";
print "\n";
print "For more information go to http://ids.surfnet.nl/\n";

