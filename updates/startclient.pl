#!/usr/bin/perl -w

#########################################
# Startup script for SURFnet IDS Sensor
# SURFnet IDS
# Version 1.02.13
# 04-09-2006
# Jan van Lith & Kees Trippelvitz
# Modified by Peter Arts
#########################################

################
# Changelog:
# 1.02.13 Rereleased as perl script
# 1.02.12 Extended error message when using static IP configuration
# 1.02.11 Fixed a small bug in test of $networkconf and $checktapip
# 1.02.10 Fixed a bug with the generation of the sensor key
# 1.02.09 Added a check for the starthook.sh script
# 1.02.08 Added hook to the starthook.sh script
# 1.02.07 Initial release
################

use File::Basename;

$basedir = "/cdrom/scripts/";
do "$basedir/perl.conf";
require "$basedir/functions.inc.pl";

$chkstatus = chksensorstatus();
if ($chkstatus == 0) {
  print "${y}Sensor has already been started.${n}\n";
  exit;
}

# Checking the existance of ca.crt
$chkca = chkca();
printmsg("Checking ca.crt:", $chkca);
if ($chkca != 0) {
  exit;
}

# Checking disabled status of the sensor
$disabled = chkdisabled();
if ($disabled != 0) {
  print "${r}Sensor is disabled by admin${n}\n";
  exit;
}

# Running user defined script in /cdrom/scripts/scripts.d/
if (-e "$basedir/scripts.d/user_startclient.pl") {
  system("$basedir/scripts.d/user_startclient.pl");
}

# Checking read/write status of the sensor
$chkrw = chkrw();
printmsg("Checking read/write status:", $chkrw);

# Giving the network interface some time to get ready.
# Fixes stuff with older or slow network cards
#for ($i=$ifcounter; $i != 0; $i--) {
#  print "Waiting for interfaces: $i\n";
#  sleep 1;
#  system("/usr/bin/clear");
#}

# Getting the network configuration method
$netconf = getnetconf();
printmsg("Network configuration method:", $netconf);

# Getting the active interface
$if = getif();
printmsg("Checking active interface:", $if);
if ($if eq "false") {
  exit;
}

if ($netconf eq "static") {
  # Check if pump is running, if so, kill it.
  $checkpump = `ps -ef | grep pump | grep -v grep | wc -l`;
  if ( $checkpump > 0 ) {
    `killall pump`;
  }

  $if_ip = getnetinfo("config", "IP_sensor");
  printmsg("Retrieving IP address:", $if_ip);
  $if_mask = getnetinfo("config", "Netmask");
  printmsg("Retrieving netmask:", $if_mask);
  $if_gw = getnetinfo("config", "Gateway");
  printmsg("Retrieving gateway:", $if_gw);
  $if_bc = getnetinfo("config", "Broadcast");
  printmsg("Retrieving broadcast address:", $if_bc);
  $if_domain = getnetinfo("config", "Domain");
  printmsg("Retrieving domain:", $if_domain);
  $if_ns = getnetinfo("config", "Nameserver");
  printmsg("Retrieving nameserver:", $if_ns);

  # Activate network configuration
  `ifconfig $if $if_ip netmask $if_mask broadcast $if_bc`;
  `route add -net default gw $if_gw`;
  open(RESOLV, ">/etc/resolv.conf");
  print RESOLV "nameserver $if_ns\n";
  print RESOLV "domain $if_domain\n";
  close(RESOLV);
} else {
  # DHCP configuration method
  # Start pump if needed
  $checkpump = `ps -ef | grep pump | grep $if | grep -v grep | wc -l`;
  if ( $checkpump == 0 ) {
    `pump -i $if 2>/dev/null`;
    printmsg("Starting DHCP client for $if:", $?);
  }
}

# Checking if the interface has received an IP
$if_ip = getifip($if);
printmsg("IP address for $if:", $if_ip);

# Checking if DNS resolving works
$chkresolv = getresolv($server);
if ($chkresolv ne "false") {
  $chkresolv = 0;
}
printmsg("Checking DNS resolver:", $chkresolv);

# Checking if the ports to the server are unfiltered
$openvpnport = getportstatus($if, 1194);
printmsg("Checking OpenVPN port:", $openvpnport);
$updateport = getportstatus($if, 4443);
printmsg("Checking updates port:", $updateport);

# Checking the version of wget
$wgetversion = getwgetversion();
printmsg("Checking wget version:", $wgetversion);
if ($wgetversion ne "1.9.1") {
  $wgetarg = "--no-check-certificate";
} else {
  $wgetarg = "";
}

# Checking wget auth
$chkwgetauth = chkwgetauth($wgetarg);
printmsg("Checking wget authentication:", $chkwgetauth);
if ($chkwgetauth != 0) {
  exit;
}

# Retrieving sensor name
$sensor = getsensor();
printmsg("Retrieving sensor name:", $sensor);

# Setting the serverurl
$serverurl = "$http://$server:$port";
if ($sensor eq "false") {
  # No sensor certificate and key found yet, retrieve them.
  `wget -q $wgetarg -O $basedir/cert.php $serverurl/cert.php?localip=$if_ip`;
  printmsg("Retrieving sensor certificates:", $?);

  # Parsing the sensor name from the downloaded certificate file
  $keyname = `tail -n1 $basedir/cert.php`;
  chomp($keyname);
  
  # Updating client.conf
  printmsg("Updating client.conf:", "info");
  open(CLIENT, "> $basedir/client.conf");
  print CLIENT "ca $basedir/ca.crt";
  print CLIENT "key $basedir/$keyname.key";
  print CLIENT "cert $basedir/$keyname.crt";
  close(CLIENT);

  # Parsing the .key and .crt file from the downloaded certificate file
  printmsg("Parsing the certificates:", "info");
  open(PHP, "$basedir/cert.php");
  open(KEY, "> $basedir/$sensor.key");
  open(CERT, "> $basedir/$sensor.crt");
  $eof = 0;
  while(<PHP>) {
    $line = $_;
    chomp($line);
    if ($line =~ /^EOF$/) {
      $eof++;
    } elsif ($eof == 0) {
      print KEY "$line\n";
    } elsif ($eof == 1) {
      print CERT "$line\n";
    } elsif ($eof == 2) {
      printmsg("Finished parsing certificates:", "info");
    } else {
      print "${r}Could not parse the following line:\n";
      print "$line${n}\n";
    }
  }
  close(PHP);
  close(KEY);
  close(CERT);
  # Finished parsing the certificate file
}

# Setting up the permissions of the .key and .crt file
`chmod 600 $basedir/$sensor.key`;
printmsg("Changing permissions sensor key:", $?);
`chmod 644 $basedir/$sensor.crt`;
printmsg("Changing permissions sensor cert:", $?);

# Creating the ifmethod string to be given to the server
if ($netconf eq "dhcp") {
  $ifmethodstring = "dhcp";
} else {
  $ifmethodstring = "$if_mask|$if_gw|$if_bc";
}

# Updating the current configuration to the server
`wget -q $wgetarg -O $basedir/startclient.php "$serverurl/startclient.php?localip=$if_ip&ifmethod=$ifmethodstring&keyname=$sensor"`;
printmsg("Updating status info to the server", $?);

# Check for errors
$err = 0;
$errcheck = `grep "ERROR" $basedir/startclient.php | wc -l`;
if ($errcheck != 0) {
  $errors = `grep "ERROR" $basedir/startclient.php`;
  chomp($errors);
  $errno = `grep "ERRNO" $basedir/startclient.php | awk '{print \$2}'`;
}

# Sync the time with a timeserver
$chktime = chktime();
printmsg("Syncing time with ntpserver:", $chktime);

# Check for errors
$err = 0;
$errcheck = `grep "ERROR" $basedir/startclient.php | wc -l`;
if ($errcheck != 0) {
  $errors = `grep "ERROR" $basedir/startclient.php`;
  chomp($errors);
  $errno = `grep "ERRNO" $basedir/startclient.php | awk '{print \$2}'`;
  if ($errno == 99) {
    print "${y}A tap IP address needs to be configured in the webinterface.\n";
    print "Start the sensor again when this is done.${n}\n";
  } else {
    print "${r}An error occurred while updating status information.\n";
    print "$errors${n}\n";
  }
}

if ($err == 0) {
  # Creating tap device
  `openvpn --mktun --dev $tap`;
  printmsg("Creating tap device:", $?);
  
  # Starting OpenVPN
  `openvpn --config $basedir/client.conf --daemon`;
  printmsg("Starting OpenVPN:", $?);
}

# Starting idsmenu
$arg = $ARGV[0];
if ($ARGV[0]) {
  if ($ARGV[0] == 1 || $ARGV[0] eq "start") {
    exec "$basedir/idsmenu";
  }
}
