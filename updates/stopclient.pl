#!/usr/bin/perl -w

#########################################
# Stop script for SURFnet IDS Sensor
# SURFnet IDS
# Version 1.02.06
# 04-09-2006
# Jan van Lith & Kees Trippelvitz
# Modified by Peter Arts
#########################################

################
# Changelog:
# 1.02.06 Rereleased as perl script
# 1.02.05 Restructured the code
# 1.02.04 Added hook to the stophook.sh script
# 1.02.03 Initial release
################

# This script is run at reboot or shutdown.

################
# Variables    #
################
$basedir="/cdrom/scripts";
do "$basedir/perl.conf";
require "$basedir/functions.inc.pl";

################
# Start script #
################

$chkbr = chkbridge();
$chkopenvpn = chkopenvpn();
if ($chkbr == 1 && $chkopenvpn == 1) {
  print "${y}The sensor is not running. Nothing to stop.${n}\n";
  exit;
}

# Check the disk for read/write status.
$chkrw = chkrw();
printmsg("Checking read/write status:", $chkrw);

# Check for static of dynamic network connection
$netconf = getnetconf();
printmsg("Network configuration method:", $netconf);

# Get the active ethernet interface
$if = getif();
printmsg("Checking active interface:", $if);

# Get the bridge interface IP address.
$if_ip = getifip($br);
printmsg("Checking IP address:", $if_ip);

# If OpenVPN is running, stop it
if ($chkopenvpn == 0) {
  # Stopping openvpn client.
  `killall openvpn`;
  printmsg("Stopping OpenVPN tunnel:", $?);
}

$chktap = `ifconfig | grep $tap | wc -l`;
if ($chktap != 0) {
  `openvpn --dev $tap --rmtun`;
  printmsg("Removing $tap device:", $?);
}

# If the bridge is present, remove it and restore the main interface
if ($chkbr == 0) {
  # Removing bridge and tap devices.
  `ifconfig $br down`;
  printmsg("Shutting down bridge interface:", $?);

  # Removing the active interface from the bridge
  `brctl delif $br $if`;
  printmsg("Removing $if from $br:", $?);

  # Checking if $tap device is present in the bridge
  $chkbrtap = `brctl show $br | grep $tap | wc -l`;
  chomp($chkbrtap);
  if ($chkbrtap != 0) {
    `brctl delif $br $tap`;
    printmsg("Removing $tap from $br:", $?);
  }

  # Removing the bridge
  `brctl delbr $br`;
  printmsg("Removing bridge interface:", $?);
}

if ($netconf eq "dhcp") {
  # If pump is running for the bridge, kill it.
  $chkpump = `ps -ef | grep -i pump | grep -v grep | wc -l`;
  if ($chkpump != 0) {
    `killall pump`;
    printmsg("Killing all dhcp clients:", $?);
  }
  `pump -i $if 2>/dev/null`;
  printmsg("Starting pump for active interface:", $?);
} elsif ($netconf eq "static") {
  $if_ip = getnetinfo("config", "IP_sensor");
  printmsg("Configured IP address:", $if_ip);
  $if_mask = getnetinfo("config", "Netmask");
  printmsg("Configured Netmask:", $if_mask);
  $if_gw = getnetinfo("config", "Gateway");
  printmsg("Configured Gateway:", $if_gw);
  $if_bc = getnetinfo("config", "Broadcast");
  printmsg("Configured Broadcast:", $if_bc);
  $if_name = getnetinfo("config", "Nameserver");
  printmsg("Configured Nameserver:", $if_name);
  $if_domain = getnetinfo("config", "Domain");
  printmsg("Configured Domain:", $if_domain);
  `ifconfig $if $if_ip netmask $if_mask broadcast $if_bc`;
  `route add -net default gw $if_gw`;
} else {
  printmsg("Unknown network configuration method:", "info");
}

# Check the wget version.
$wgetv = getwgetversion();
if ($wgetv ne "1.9.1") {
  $wgetarg = "--no-check-certificate";
} else {
  $wgetarg = "";
}

# Check if wget authentication is correct.
$chkwgetauth = chkwgetauth($wgetarg);
printmsg("Checking wget authentication:", $chkwgetauth);

# Get the keyname.
$sensor = getsensor();

# Check if DNS name resolving works
$chkresolv = getresolv($server);
if ($chkresolv eq "false") {
  $chkresolv = 1;
} else {
  $chkresolv = 0;
}
printmsg("Checking DNS resolver:", $chkresolv);

# Generate the server URL
$serverurl = "$http://$server:$port";

# Get the localip.
$if_ip = getifip($if);
if ($netconf ne "static") {
  printmsg("Checking new IP address:", $if_ip);
}
if ($chkresolv == 0) {
  `wget -q $wgetarg -O $basedir/stopclient.php "$serverurl/stopclient.php?localip=$if_ip&keyname=$sensor"`;
  printmsg("Updating status information:", $?);
}

# Check for errors with the localip and tapip update.
$checkerr = `cat $basedir/stopclient.php | grep "ERROR" | wc -l`;
if ($checkerr > 0) {
  # Errors occured while updating localip and tapip.
  $errors = `cat $basedir/stopclient.php | grep "ERROR"`;
  print "${y}Error occured while updating status information.\n${n}";
  print "${r}$errors\n${n}";
}

# Add a hook to userdefined commands/actions that could be run.
if (-e "$basedir/scripts.d/user_stopclient.pl") {
  `$basedir/scripts.d/user_stopclient.pl`;
  printmsg("Starting user_stopclient.pl:", $?);
}
