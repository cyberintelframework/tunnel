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

dbconnect();

$sql = "SELECT sensors.id FROM sensors, sensor_details WHERE sensors.keyname = sensor_details.keyname AND (status = 1 OR status = 6) AND NOT permanent = 1";
$sth = $dbh->prepare($sql);
$er = $sth->execute();

while (@row = $sth->fetchrow_array) {
  $sid = $row[0];
  $sql = "UPDATE sensors SET tap = '', tapip = NULL, status = 0 WHERE id = '$sid'";
  $er = $dbh->do($sql);
}

