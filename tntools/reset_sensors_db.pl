#!/usr/bin/perl

####################################
# Reset database sensors           #
# SURFids 3.00                     #
# Changeset 001                    #
# 29-08-2008                       #
# Jan van Lith & Kees Trippelvitz  #
####################################

#####################
# Changelog:
# 001 Initial release
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

connectdb();

$sql = "SELECT id, netconf, tap FROM sensors WHERE status = 1";
$sth = $dbh->prepare($sql);
$er = $sth->execute();

while (@row = $sth->fetchrow_array) {
  $sid = $row[0];
  $netconf = $row[1];
  $tap = $row[2];

  if ("$tap" ne "") {
    if ($netconf eq "dhcp" || $netconf eq "vland") {
      $sql = "UPDATE sensors SET tap = '', tapip = NULL, status = 0 WHERE tap = '$tap'";
      $er = $dbh->do($sql);
    } elsif ($netconf eq "static" || $netconf eq "vlans") {
      $sql = "UPDATE sensors SET tap = '', status = 0 WHERE tap = '$tap'";
      $er = $dbh->do($sql);
    }
  }
}

