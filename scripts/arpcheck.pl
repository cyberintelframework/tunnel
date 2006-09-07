#!/usr/bin/perl

########################################
# ARP check script for SURFnet IDS     #
# SURFnet IDS                          #
# Version 1.02.01                      #
# 08-06-2006                           #
# Jan van Lith & Kees Trippelvitz      #
########################################

#########################################################################################
# Copyright (C) 2005 SURFnet                                                            #
# Authors Jan van Lith & Kees Trippelvitz                                               #
#                                                                                       #
# This program is free software; you can redistribute it and/or                         #
# modify it under the terms of the GNU General Public License                           #
# as published by the Free Software Foundation; either version 2                        #
# of the License, or (at your option) any later version.                                #
#                                                                                       #
# This program is distributed in the hope that it will be useful,                       #
# but WITHOUT ANY WARRANTY; without even the implied warranty of                        #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                         #
# GNU General Public License for more details.                                          #
#                                                                                       #
# You should have received a copy of the GNU General Public License                     #
# along with this program; if not, write to the Free Software                           #
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.       #
#                                                                                       #
# Contact ids@surfnet.nl                                                                #
#########################################################################################

#############################################
# Changelog:
# 1.02.01 Initial release
#############################################

##################
# Modules used
##################
use DBI;
use Time::localtime;
use Time::Local;

##################
# Variables used
##################
do '/etc/surfnetids/surfnetids-tn.conf';
$logfile =~ s|.*/||;
if ($logstamp == 1) {
  $day = localtime->mday();
  if ($day < 10) {
    $day = "0" . $day;
  }
  $month = localtime->mon() + 1;
  if ($month < 10) {
    $month = "0" . $month;
  }
  $year = localtime->year() + 1900;
  if ( ! -d "$surfidsdir/log/$day$month$year" ) {
    mkdir("$surfidsdir/log/$day$month$year");
  }
  $logfile = "$surfidsdir/log/$day$month$year/$logfile";
}
else {
  $logfile = "$surfidsdir/log/$logfile";
}

##################
# Functions
##################

sub getts {
  my $ts = time();
  my $tsyear = localtime->year() + 1900;
  my $tsmonth = localtime->mon() + 1;
  if ($tsmonth < 10) {
    $tsmonth = "0" . $tsmonth;
  }
  my $tsday = localtime->mday();
  if ($tsday < 10) {
    $tsday = "0" . $tsday;
  }
  my $tshour = localtime->hour();
  if ($tshour < 10) {
    $tshour = "0" . $tshour;
  }
  my $tsmin = localtime->min();
  if ($tsmin < 10) {
    $tsmin = "0" . $tsmin;
  }
  my $tssec = localtime->sec();
  if ($tssec < 10) {
    $tssec = "0" . $tssec;
  }

  my $timestamp = "$tsday-$tsmonth-$tsyear $tshour:$tsmin:$tssec";
}

##################
# Main script
##################

# Opening log file
open(LOG, ">> $logfile");
$ts = getts();
print LOG "[$ts] Starting arpmon.pl\n";

# Connect to the database (dbh = DatabaseHandler or linkserver)
$dbh = DBI->connect($dsn, $pgsql_user, $pgsql_pass)
        or die $DBI::errstr;
$ts = getts();
print LOG "[$ts] Connecting to $pgsql_dbname with DSN: $dsn\n";
print LOG "[$ts] Connect result: $dbh\n";

$sql_arp = "SELECT mac, ip, sensor FROM arp_static";
$sth_arp = $dbh->prepare($sql_arp);
$result_arp = $sth_arp->execute();

while(@static_arp = $sth_arp->fetchrow_array) {
  $mac = $static_arp[0];
  $ip = $static_arp[1];
  $sensor = $static_arp[2];

  $sql_sensor = "SELECT tap FROM sensors WHERE id = $sensor";
  $sth_sensor = $dbh->prepare($sql_sensor);
  $result_sensor = $sth_sensor->execute();
  @row_sensor = $sth_sensor->fetchrow_array();
  $tap = $row_sensor[0];

  $scan_result = `arping -c 1 -d -r -R -i $tap $ip`;
  @scan_result_ar = split(/ /, $scan_result);
  $scan_mac = $scan_result_ar[0]; 
  $scan_ip = $scan_result_ar[1]; 

  $timestamp = time();

  if ($scan_mac ne $mac) {
    $alert = "MAC - IP mismatch";
    $detail = "$ip has MAC address $scan_mac. This should be $mac.";
    $sql_log = "INSERT INTO arp_log (timestamp, sensorid, alert, detail) VALUES ($timestamp, $sensor, '$alert', '$detail')";
    $sth_log = $dbh->prepare($sql_log);
    $result_log = $sth_log->execute();
    print "ARP alert!\n";
  }
  else {
    print "Ok\n";
  }
}
close(LOG);
# Closing database connection.
$dbh = "";
#$dbh->disconnect;

