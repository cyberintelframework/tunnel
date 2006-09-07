#!/usr/bin/perl -w

$tap = $ARGV[0];
print "TAP: $tap\n";
$tapip = `ifconfig $tap | grep -v inet6 | grep -i "inet" | cut -d":" -f2 | cut -d" " -f1`;
$tapmask = `ifconfig $tap | grep -v inet6 | grep -i "inet" | cut -d":" -f4 | cut -d" " -f1`;
chomp($tapip);
chomp($tapmask);
print "TAPIP: $tapip";
print "TAPMASK: $tapmask";

$hostmin = `/opt/surfnetids/scripts/ipcalc 192.168.10.10 255.255.255.0 | grep -i hostmin`;
chomp($hostmin);

#print "HOSTMIN: $hostmin";
