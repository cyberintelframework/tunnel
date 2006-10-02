#!/usr/bin/perl

#########################################
# Checktap script for IDS tunnel server #
# SURFnet IDS                           #
# Version 1.02.02                       #
# 24-08-2006                            #
# Jan van Lith & Kees Trippelvitz       #
#########################################

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

#####################
# Changelog:
# 1.02.02 Adding an ignore on static network configuration
# 1.02.01 Initial release
#####################

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

# Opening log file
open(LOG, ">> $logfile");

# Get the tap device.
$tap = $ARGV[0];

$ts = getts();
print LOG "[$ts - $tap] Starting checktap.pl\n";

# Connect to the database (dbh = DatabaseHandler or linkserver)
$dbh = DBI->connect($dsn, $pgsql_user, $pgsql_pass)
      or die $DBI::errstr;
$ts = getts();
print LOG "[$ts - $tap] Connected to $pgsql_dbname with DSN: $dsn\n";
print LOG "[$ts - $tap] Connect result: $dbh\n";

# Prepare and execute sql query on database to retrieve tapip.
$sth = $dbh->prepare("SELECT tapip, netconf FROM sensors WHERE tap = '$tap'");
$ts = getts();
print LOG "[$ts - $tap] Prepared query: SELECT tapip, netconf FROM sensors WHERE tap = '$tap'\n";
$execute_result = $sth->execute();

# Get the tap ip address of tap device ($tap) from the query result.
@row = $sth->fetchrow_array;
$ts = getts();
$db_tapip = $row[0];
$db_netconf = $row[1];
print LOG "[$ts - $tap] DB Tap IP address: $db_tapip\n";
print LOG "[$ts - $tap] DB netconf: $db_netconf\n";

# Get the actual IP address of the tap device.
$tapip = `ifconfig $tap | grep "inet addr:" | cut -d":" -f2 | cut -d" " -f1`;
chomp($tapip);
$ts = getts();
$ec = getec();
print LOG "[$ts - $tap - $ec] IP address of $tap: $tapip\n"; 

if ($db_netconf eq "dhcp") {
  # If the tap IP addresses don't match, fix it.
  if ($tapip eq $db_tapip) {
    print LOG "[$ts - $tap] No change of tap IP address. No need to update.\n";
  }
  else {
    print LOG "[$ts - $tap] Updating the Tap IP address in the database.\n";
    $execute_result = $dbh->do("UPDATE sensors SET tapip = '$tapip' WHERE tap = '$tap'");
    $ts = getts();
    print LOG "[$ts - $tap] Prepared query: UPDATE sensors SET tapip = '$tapip' WHERE tap = '$tap'\n";
    print LOG "[$ts - $tap] Executed query: $execute_result\n";
  }
} else {
  print LOG "[$ts - $tap] Ignoring $db_netconf configuration.\n";
}

# Closing database connection.
$dbh = "";

print LOG "----------------finished checktap.pl------------\n";

# Closing logfile filehandle.
close(LOG);

