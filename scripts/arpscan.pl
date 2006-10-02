#!/usr/bin/perl

########################################
# IDMEF script for IDS server database #
# SURFnet IDS                          #
# Version 1.02.02                      #
# 12-04-2006                           #
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

##################
# Modules used
##################
use DBI;
use Time::localtime;
use Time::Local;

##################
# Variables used
##################
do '/etc/surfnetids/surfnetids-log.conf';
$tap = $ARGV[0];
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
  if ( ! -d "$surfidsdir/log/$day$month$year/$tap" ) {
    mkdir("$surfidsdir/log/$day$month$year/$tap");
  }
  $logfile = "$surfidsdir/log/$day$month$year/$tap/$logfile";
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

$sth = $dbh->prepare("SELECT id, keyname FROM sensors WHERE tap = '$tap'");
$execute_result = $sth->execute();
@row = $sth->fetchrow_array;
$sensorid = $row[0];
$sensor = $row[1];

$tapip = `ifconfig $tap | grep -v inet6 | grep "inet" | cut -d":" -f2 | cut -d" " -f1`;
$tapmask = `ifconfig $tap | grep -v inet6 | grep "inet" | cut -d":" -f4 | cut -d" " -f1`;
chomp($tapip);
chomp($tapmask);

$hostmin = `$surfidsdir/scripts/ipcalc $tapip $tapmask | grep -i hostmin | awk '{print \$2}'`;
chomp($hostmin);
$hostmax = `$surfidsdir/scripts/ipcalc $tapip $tapmask | grep -i hostmax | awk '{print \$2}'`;
chomp($hostmax);
@min_ar = split(/\./, $hostmin);
@max_ar = split(/\./, $hostmax);

print "ARP scanning $tap from $hostmin to $hostmax\n";
for ($a=$min_ar[0]; $a<=$max_ar[0]; $a++) {
  for ($b=$min_ar[1]; $b<=$max_ar[1]; $b++) {
    for ($c=$min_ar[2]; $c<=$max_ar[2]; $c++) {
      for ($d=$min_ar[3]; $d<=$max_ar[3]; $d++) {
        $scan_result = `arping -c 1 -r -R -i $tap $a.$b.$c.$d`;
        print "ARPING: $a.$b.$c.$d\n";
#        if ($scan_result ne "") {
#          @scan_ar = split(/ /, $scan_result);
#          $mac = $scan_ar[0];
#          chomp($mac);
#          $ip = $scan_ar[1];
#          chomp($ip);
#          $timestamp = time();

#          $sth = $dbh->prepare("SELECT ip FROM arp_cache WHERE mac = '$mac'");
#          $execute_result = $sth->execute();
#          @row = $sth->fetchrow_array;
#          $cache_ip = $row[0];

#          if ($cache_ip eq "") {
#            print LOG "[$ts - $tap] New cache entry: $mac.\n";
#            $sql_insert = "INSERT INTO arp_cache (timestamp, mac, ip, sensorid) VALUES ($timestamp, '$mac', '$ip', $sensorid)";
#            $sth = $dbh->prepare($sql_insert);
#            $execute_result = $sth->execute();
#          }
#          elsif ("$ip" ne "$cache_ip") {
#            print LOG "[$ts - $tap - Query] IP changed for $mac.\n";
#            $sql_insert = "INSERT INTO arp_log (timestamp, mac, old_ip, new_ip, sensorid) VALUES ($timestamp, '$mac', '$cache_ip', '$ip', $sensorid)";
#            $sth = $dbh->prepare($sql_insert);
#            $execute_result = $sth->execute();

#            $sql_update = "UPDATE arp_cache SET ip = '$ip' WHERE mac = '$mac' AND sensorid = $sensorid";
#            $sth = $dbh->prepare($sql_update);
#            $execute_result = $sth->execute();
#          }
#          else {
#            print LOG "[$ts - $tap - Query] Updated timestamp for $mac.\n";
#            $sql_update = "UPDATE arp_cache SET timestamp = '$timestamp' WHERE mac = '$mac' AND sensorid = $sensorid";
#            $sth = $dbh->prepare($sql_update);
#            $execute_result = $sth->execute();
#          }
#        }
      }
    }
  }
}
close(LOG);
# Closing database connection.
#$dbh->disconnect;
$dbh = "";

