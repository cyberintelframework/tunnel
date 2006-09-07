#!/usr/bin/perl

###################################
#     SQL script for IDS server   #
#           SURFnet IDS           #
#           Version 1.07          #
#            13-01-2006           #
# Jan van Lith & Kees Trippelvitz #
###################################

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

##################
# Variables used
##################
do '/etc/surfnetids/surfnetids-tn.conf';
$logfile =~ s|.*/||;
$logfile = "$surfidsdir/log/$logfile";
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
  $logfile = "$logfile-$day$month$year";
}

##################
# Functions
##################

sub getts {
  my $ts = time();
  my $year = localtime->year() + 1900;
  my $month = localtime->mon() + 1;
  if ($month < 10) {
    $month = "0" . $month;
  }
  my $day = localtime->mday();
  if ($day < 10) {
    $day = "0" . $day;
  }
  my $hour = localtime->hour();
  if ($hour < 10) {
    $hour = "0" . $hour;
  }
  my $min = localtime->min();
  if ($min < 10) {
    $min = "0" . $min;
  }
  my $sec = localtime->sec();
  if ($sec < 10) {
    $sec = "0" . $sec;
  }

  my $timestamp = "$day-$month-$year $hour:$min:$sec";
}

sub getec {
  if ($? == 0) {
    my $ec = "Ok";
  }
  else {
    my $ec = "Err - $?";
  }
}

##################
# Main script
##################

$err = 0;

# Opening log file
open(LOG, ">> $logfile");

# Get the sensor name and tap device.
$tap = $ARGV[0];
$sensor = $ARGV[1];

$ts = getts();
print LOG "[$ts - $tap] Starting sql.pl\n";

$count = 0;
$i = 0;
while ($count == 0 && $i < $sql_dhcp_retries) {
  $tapcheck = `ifconfig $tap`;
  if ($? != 0) {
    $count = 1;
    $ts = getts();
    $ec = getec();
    print LOG "[$ts - $tap - $ec] Error: The tap device was not present.\n";
    $err = 1;
    break;
  }
  else {
    $count = `ifconfig $tap | grep "inet addr:" | wc -l`;
    chomp($count);
  }
  $i++;
  if ($i == $sql_dhcp_retries) {
    print LOG "[$ts - $tap] Error: The tap device could not get an IP address.\n";
    $err = 1;
  }
  sleep 1;
}

if ($err == 0) {
  $ts = getts();
  $ec = getec();
  print LOG "[$ts - $tap - $ec] $tap device is up. Checking ip address.\n";

  # Get the IP address from the tap interface.
  $tap_ip = `ifconfig $tap | grep "inet addr:"`;
  chomp($tap_ip);
  @first_ar = split(/ +/,$tap_ip);
  $tap_ip = $first_ar[2];
  @second_ar = split(/:/,$tap_ip);
  $tap_ip = $second_ar[1];
  chomp($tap_ip);
  $ts = getts();
  $ec = getec();
  print LOG "[$ts - $tap - $ec] Tap ip address: $tap_ip\n";

  # Connect to the database (dbh = DatabaseHandler or linkserver)
  $dbh = DBI->connect($dsn, $pgsql_user, $pgsql_pass)
        or die $DBI::errstr;
  $ts = getts();
  print LOG "[$ts - $tap] Connected to $pgsql_dbname with DSN: $dsn\n";
  print LOG "[$ts - $tap] Connect result: $dbh\n";

  # Update Tap info to the database for the current $sensor.
  $execute_result = $dbh->do("UPDATE sensors SET tap = '$tap', tapip = '$tap_ip' WHERE keyname = '$sensor'");
  $ts = getts();
  print LOG "[$ts - $tap] Prepared query: UPDATE sensors SET tap = '$tap', tapip = '$tap_ip' WHERE keyname = '$sensor'\n";
  print LOG "[$ts - $tap] Executed query: $execute_result\n";

  # Closing database connection.
  $dbh->disconnect;
}

print LOG "----------------finished sql.pl------------\n";

# Closing logfile filehandle.
close(LOG);
