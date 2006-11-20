#!/usr/bin/perl

#########################################
# Checktap script for IDS tunnel server #
# SURFnet IDS                           #
# Version 1.04.02                       #
# 20-11-2006                            #
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
# 1.04.02 Included tnfunctions.inc.pl and modified code structure
# 1.04.01 Code layout
# 1.03.01 Released as part of the 1.03 package
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
require "$surfidsdir/scripts/tnfunctions.inc.pl";

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
} else {
  $logfile = "$surfidsdir/log/$logfile";
}

##################
# Main script
##################

# Opening log file
open(LOG, ">> $logfile");

# Get the tap device.
$tap = $ARGV[0];

printlog("Starting checktap.pl");

# Connect to the database (dbh = DatabaseHandler or linkserver)
$dbconn = connectdb();

if ("$dbconn" ne "false") {
  # Prepare and execute sql query on database to retrieve tapip.
  $sql = "SELECT tapip, netconf FROM sensors WHERE tap = '$tap'";
  $sth = $dbh->prepare($sql);
  printlog("Prepared query: $sql");
  $er = $sth->execute();
  printlog("Executed query: $er");

  # Get the tap ip address of tap device ($tap) from the query result.
  @row = $sth->fetchrow_array;
  $ts = getts();
  $db_tapip = $row[0];
  $db_netconf = $row[1];
  printlog("DB Tap IP address: $db_tapip");
  printlog("DB netconf: $db_netconf");

  # Get the actual IP address of the tap device.
  $tapip = getifip($tap);
  chomp($tapip);
  printlog("IP address of $tap: $tapip);

  if ($db_netconf eq "dhcp" && "$tapip" ne "false") {
    # If the tap IP addresses don't match, fix it.
    if ($tapip ne $db_tapip) {
      printlog("Updating the tap IP address in the database");
      $sql = "UPDATE sensors SET tapip = '$tapip' WHERE tap = '$tap'";
      $er = $dbh->do($sql);
      printlog("Prepared query: $sql");
      printlog("Executed query: $er");
    }
  }

  # Closing database connection.
  $dbh = "";
}

printlog("----------------finished checktap.pl------------");

# Closing logfile filehandle.
close(LOG);

