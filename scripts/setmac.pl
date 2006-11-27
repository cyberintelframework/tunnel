#!/usr/bin/perl

###################################
# Setmac script for IDS server    #
# SURFnet IDS                     #
# Version 1.02.02                 #
# 23-05-2006                      #
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

#####################
# Changelog:
# 1.02.02 Fixed a bug with the netconf query
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
# Get tap device that's coming up.
$tap = $ENV{dev};

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

# Get sensor name.
$sensor = $ENV{common_name};

# Opening log file
open(LOG, ">> $logfile");

#print LOG "=================================\n";
#foreach $key (sort keys(%ENV)) {
#  print LOG "$key = $ENV{$key}\n";
#}
#print LOG "=================================\n";

$ts = getts();
print LOG "[$ts - $tap] Starting setmac.pl\n";
print LOG "[$ts - $tap] Sensor: $sensor\n";

# Check for tap existance.
`ifconfig $tap`;

if ($? == 0) {

  $ec = getec();
  print LOG "[$ts - $tap - $ec] Tap device exists.\n";

  # Connect to the database (dbh = DatabaseHandler or linkserver)
  $dbh = DBI->connect($dsn, $pgsql_user, $pgsql_pass)
        or die $DBI::errstr;
  $ts = getts();
  print LOG "[$ts - $tap] Connected to $pgsql_dbname with DSN: $dsn\n";
  print LOG "[$ts - $tap] Connect result: $dbh\n";

  # Get the mac address for the sensor from the database.
  $sth = $dbh->prepare("SELECT mac FROM sensors WHERE keyname = '$sensor'");
  $ts = getts();
  print LOG "[$ts - $tap] Prepared query: SELECT mac FROM sensors WHERE keyname = '$sensor'\n";
  $execute_result = $sth->execute();
  $ts = getts();
  print LOG "[$ts - $tap] Executed query: $execute_result\n";

  @row = $sth->fetchrow_array;
  $ts = getts();
  $mac = $row[0];
  if ($mac eq "") {
    # If no mac address is present in the database, add the generated one from OpenVPN to the database.
    print LOG "[$ts - $tap] No MAC address in sensors table for $sensor.\n";
    $mac = `ifconfig $tap | grep HWaddr`;
    @mac_ar = split(/ +/, $mac);
    $mac = $mac_ar[4];
    $ts = getts();
    $ec = getec();
    print LOG "[$ts - $tap - $ec] New MAC address: $mac.\n";
    $execute_result = $dbh->do("UPDATE sensors SET mac = '$mac' WHERE keyname = '$sensor'");
    $ts = getts();
    print LOG "[$ts - $tap] Prepared query: UPDATE sensors SET mac = '$mac' WHERE keyname = '$sensor'\n";
    print LOG "[$ts - $tap] Executed query: $execute_result\n";
  }
  else {
    # MAC address is present in the database, update the interface with the new mac.
    print LOG "[$ts - $tap] MAC address already known.\n";
    `ifconfig $tap hw ether $mac`;
    $ts = getts();
    $ec = getec();
    print LOG "[$ts - $tap - $ec] MAC address of $tap set to $mac.\n";
  }

  # Get the network config method.
  $sth = $dbh->prepare("SELECT netconf, tapip FROM sensors WHERE keyname = '$sensor'");
  $ts = getts();
  print LOG "[$ts - $tap] Prepared query: SELECT netconf, tapip FROM sensors WHERE keyname = '$sensor'\n";
  $execute_result = $sth->execute();
  $ts = getts();
  print LOG "[$ts - $tap] Executed query: $execute_result\n";

  @row = $sth->fetchrow_array;
  $ts = getts();
  $netconf = $row[0];
  $tapip = $row[1];

  if ($netconf eq "dhcp") {
    # Start the sql.pl script to update all tap device information to the database.
    system "$surfidsdir/scripts/sql.pl $tap $sensor &";
    print LOG "[$ts - $tap] Network config method: DHCP\n";
    print LOG "[$ts - $tap] Started sql script: $surfidsdir/scripts/sql.pl $tap $sensor\n";
  }
  elsif ($netconf ne "" && $tapip ne "") {
    # Start the sql.pl script to update all tap device information to the database.
    system "$surfidsdir/scripts/sql.pl $tap $sensor &";
    print LOG "[$ts - $tap] Network config method: static\n";
    print LOG "[$ts - $tap] Started sql script: $surfidsdir/scripts/sql.pl $tap $sensor\n";
  }
  elsif ($netconf ne "" && $tapip eq "") {
    print LOG "[$ts - $tap] Network config method: static\n";
    print LOG "[$ts - $tap - Err] No tap IP address specified.\n";
  }
  else {
    # The script should never come here.
    # Start the sql.pl script to update all tap device information to the database.
    system "$surfidsdir/scripts/sql.pl $tap $sensor &";
    print LOG "[$ts - $tap] Possible error. Netconf was empty. Trying DHCP.\n";
    print LOG "[$ts - $tap] Network config method: DHCP\n";
    print LOG "[$ts - $tap] Started sql script: $surfidsdir/scripts/sql.pl $tap $sensor\n";
  }

  print LOG "-------------Finished setmac.pl-------------\n";
  close(LOG);
  exit 0;
}
else {
  $ec = getec();
  print LOG "[$ts - $tap - $ec] Tap device does not exist.\n";

  print LOG "-------------Finished setmac.pl-------------\n";
  close(LOG);
  exit 1;
}
