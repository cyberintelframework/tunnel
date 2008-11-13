#!/usr/bin/perl

###################################
# Local sensor script             #
# SURFnet IDS                     #
# Version 2.10.02                 #
# 29-10-2007                      #
# Jan van Lith & Kees Trippelvitz #
###################################

#####################
# Changelog:
# 2.10.02 Added usage info on failure
# 2.10.01 Initial version
#####################

##################
# Modules used
##################
use DBI;
use Time::localtime qw(localtime);

##################
# Variables used
##################
do '/etc/surfnetids/surfnetids-tn.conf';
require "$c_surfidsdir/scripts/tnfunctions.inc.pl";
$logfile = "";
$keyname = "nepenthes";
$ts = time;

##################
# Main script
##################
if (!$ARGV[0]) {
  print "No interface given!\n";
  print "Usage: ./localsensor eth0\n";
  exit 1;
} else {
  $if = $ARGV[0];
  chomp($if);
}

$ifip = getifip($if);
chomp($ifip);
$ifmac = `ifconfig $if | head -n1 | awk -F" " '{print \$5}'`;
chomp($ifmac);

$chk = connectdb();
$sql = "SELECT id, organisation FROM sensors WHERE keyname = 'nepenthes'";
$sth = $dbh->prepare($sql);
$er = $sth->execute();

@row = $sth->fetchrow_array;
$id = $row[0];
$orgid = $row[1];
if (!$id) {
  $id = "";
}

if ("$id" eq "") {
  $sql = "SELECT id FROM organisations WHERE organisation = 'LOCAL'";
  $sth = $dbh->prepare($sql);
  $er = $sth->execute();

  @row = $sth->fetchrow_array;
  $orgid = $row[0];

  if (!$orgid) {
    $orgid = "";
  }

  if ("$orgid" eq "") {
    $sql = "INSERT INTO organisations (organisation) VALUES ('LOCAL')";
    $sth = $dbh->prepare($sql);
    $er = $sth->execute();

    $sql = "SELECT id FROM organisations WHERE organisation = 'LOCAL'";
    $sth = $dbh->prepare($sql);
    $er = $sth->execute();

    @row = $sth->fetchrow_array;
    $orgid = $row[0];
  }

  $sql = "INSERT INTO sensors (keyname, remoteip, localip, lastupdate, laststart, status, uptime, tap, tapip, mac, netconf, organisation) ";
  $sql .= " VALUES ('$keyname', '$ifip', '$ifip', $ts, $ts, 1, 0, '$if', '$ifip', '$ifmac', 'dhcp', $orgid)";
  $sth = $dbh->prepare($sql);
  $er = $sth->execute();
} else {
  $sql = "UPDATE sensors SET remoteip = '$ifip', localip = '$ifip', ";
  $sql .= " tap = '$if', tapip = '$ifip', mac = '$ifmac'  ";
  $sql .= " WHERE keyname = '$keyname' ";
  $sth = $dbh->prepare($sql);
  $er = $sth->execute();
}

printlog("Local interface added as sensor!");