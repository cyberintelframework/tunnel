#!/usr/bin/perl -w

###################################
# Stop script for IDS server	  #
# SURFnet IDS                     #
# Version 1.04.03                 #
# 13-11-2006                      #
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
# 1.04.03 Included tnfunctions.inc.pl and modified code structure
# 1.04.02 Added vlan support
# 1.04.01 Code layout
# 1.03.02 Fixed status update
# 1.03.01 Changed version to 1.03.01
# 1.02.05 Killing dhclient3 correctly if multiple instances are running
# 1.02.04 Fixed a bug with removing the route to the sensor
# 1.02.03 Changed the way dhclient3 gets killed
# 1.02.02 Added SQL query for resetting status
# 1.02.01 Initial release
#####################

####################
# Modules used
####################
use DBI;
use Time::localtime;

####################
# Variables used
####################
# Get tap device that's going down.
$tap = $ARGV[0];

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
  if ( ! -d "$surfidsdir/log/$day$month$year/$tap" ) {
    mkdir("$surfidsdir/log/$day$month$year/$tap");
  }
  $logfile = "$surfidsdir/log/$day$month$year/$tap/$logfile";
} else {
  $logfile = "$surfidsdir/log/$logfile";
}

####################
# Main script
####################

# Opening log file
open(LOG, ">> $logfile");

$ts = getts();
printlog("Starting down.pl");
#print LOG "[$ts - $tap] Starting down.pl\n";

# Connect to the database (dbh = DatabaseHandler or linkserver)
$dbconn = connectdb();

if ($dbconn eq "true") {
  # Reset status
  $sql = "UPDATE sensors SET status = 0 WHERE tap = '$tap'";
  $sth = $dbh->prepare($sql);
  $ts = getts();
  printlog("Prepared query: $sql");
  $er = $sth->execute();
  $ts = getts();
  printlog("Executed query: $er");
}

$killresult = killdhclient($tap);

# Delete .leases file
`rm -f /var/lib/dhcp3/$tap.leases`;
$ec = getec();
printlog("Deleted dhcp lease file /var/lib/dhcp3/$tap.leases", $ec);

$result = deliprules($tap);

if ($dbconn eq "true") {
  # Get the remote IP address.
  $remoteip = $ENV{REMOTE_HOST};
  if ( ! $remoteip ) {
    # Remote IP address was not set in the environment variables. Get it from the database.
    # Prepare and execute sql query on database to retrieve remoteip.
    $remoteip = dbremoteip($tap);
  }
  printlog("Remoteip: $remoteip");

  # Get the network config method. (Static / DHCP)
  $netconf = dbnetconf($tap);

  if ($netconf eq "dhcp" || $netconf eq "" || $netconf eq "vland") {
    # Network configuration method was DHCP. We delete both the tap device and address from the database.
    printlog("Network config method: DHCP");
    # Execute query to remove tap device information from database.
    $sql = "UPDATE sensors SET tap = '', tapip = NULL, status = 0 WHERE tap = '$tap'";
    $er = $dbh->do($sql);
    $ts = getts();
    printlog("Prepared query: $sql");
    printlog("Executed query: $er");
  } else {
    # Network configuration method was Static. We don't delete the tap IP address from the database.
    printlog("Network config method: static");
    # Execute query to remove tap device information from database.
    $sql = "UPDATE sensors SET tap = '', status = 0 WHERE tap = '$tap'";
    $er = $dbh->do($sql);
    $ts = getts();
    printlog("Prepared query: $sql");
    printlog("Executed query: $er");
  }

  # Delete route to connecting ip address of client via local gateway.
  $sql = "SELECT COUNT(remoteip) FROM sensors WHERE remoteip = '$remoteip'";
  $sth = $dbh->prepare($sql);
  $ts = getts();
  printlog("Prepared query: $sql");
  $er = $sth->execute();
  $ts = getts();
  printlog("Executed query: $er");

  # Get the count of remote ip addresses from the query result.
  @row = $sth->fetchrow_array;
  $ts = getts();
  $count = $row[0];
  printlog("Query result: count = $count");
  if ($count == 1) {
    # There is only 1 remoteip address in the database so we can delete the static route towards this IP.
    `route del -host $remoteip`;
    $ts = getts();
    $ec = getec();
    printlog("Deleted route: route del -host $remoteip", "$ec");
  }
} else {
  $remoteip = $ENV{REMOTE_HOST};
  `route del -host $remoteip`;
  $ts = getts();
  $ec = getec();
  printlog("Deleted route: route del -host $remoteip", "$ec");
}

# Flush the routing table of the tap device just to be sure.
$result = flushroutes($tap);
$ec = getec();
printlog("Flushing routing table for $tap", $ec);

# Closing database connection.
$dbh = "";

$ts = getts();
printlog("-------------finished down.pl-----------");

# Closing log filehandle.
close(LOG);
