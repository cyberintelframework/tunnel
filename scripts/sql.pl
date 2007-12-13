#!/usr/bin/perl

###################################
# SQL script for IDS server       #
# SURFnet IDS                     #
# Version 2.00.01                 #
# 14-09-2007                      #
# Jan van Lith & Kees Trippelvitz #
###################################
# Contributors:                   #
# Peter Arts                      #
###################################

#########################################################################################
# Copyright (C) 2005 SURFnet                                                            #
# Authors Jan van Lith & Kees Trippelvitz                                               #
# Modified by Peter Arts                                                                #
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
# 2.00.01 version 2.00
# 1.04.07 Added detectarp.pl stuff
# 1.04.06 Removed pcap.pl script
# 1.04.05 Removed arp from query
# 1.04.04 Included tnfunctions.inc.pl and modified code structure
# 1.04.03 Added vlan support 
# 1.04.02 Added ARP monitoring support
# 1.04.01 Rereleased as 1.04.01
# 1.03.03 Added the actual sql query for status updates
# 1.03.02 Added status update
# 1.03.01 Released as part of the 1.03 package
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
# Get the tap device.
$tap = $ARGV[0];

do '/etc/surfnetids/surfnetids-tn.conf';
require "$c_surfidsdir/scripts/tnfunctions.inc.pl";

$logfile = $c_logfile;
$logfile =~ s|.*/||;
if ($c_logstamp == 1) {
  $day = localtime->mday();
  if ($day < 10) {
    $day = "0" . $day;
  }
  $month = localtime->mon() + 1;
  if ($month < 10) {
    $month = "0" . $month;
  }
  $year = localtime->year() + 1900;
  if ( ! -d "$c_surfidsdir/log/$day$month$year" ) {
    mkdir("$c_surfidsdir/log/$day$month$year");
  }
  if ( ! -d "$c_surfidsdir/log/$day$month$year/$tap" ) {
    mkdir("$c_surfidsdir/log/$day$month$year/$tap");
  }
  $logfile = "$c_surfidsdir/log/$day$month$year/$tap/$logfile";
} else {
  $logfile = "$c_surfidsdir/log/$logfile";
}

##################
# Main script
##################

$err = 0;

# Opening log file
open(LOG, ">> $logfile");

# Get the sensor name.
$sensor = $ARGV[1];
$remoteip = $ARGV[2];

printlog("Starting sql.pl for $sensor on $tap!");

$dbconn = connectdb();

# Get the IP address configuration for the tap device from the database.
$sql = "SELECT netconf, netconfdetail, tapip, arp, id FROM sensors WHERE keyname = '$sensor' AND remoteip = '$remoteip'";
$sth = $dbh->prepare($sql);
printlog("Prepared query: $sql");
$er = $sth->execute();
printlog("Executed query: $er");

@row = $sth->fetchrow_array;
$netconf = $row[0];
$netconfdetail = $row[1];
$tapip = $row[2];
$arp = $row[3];
$sensorid = $row[4];

# Closing database connection.
$dbh->disconnect;

# Sleep till tunnel is fully ready 
sleep 2;

printlog("Network config method: $netconf");
$result = killdhclient($tap);  

if ($netconf eq "dhcp" || $netconf eq "vland") {
  # Start the dhcp client
  $result = startdhcp($tap);
} else { 
  # Set static network configuration without gateway, dns and resolv.conf
  # Format of netconfig: 0=>netmask|1=>gateway|2=>broadcast
  @netconfig = split(/\|/, $netconfdetail);

  $if_net = $netconfig[0];
  $if_gw = $netconfig[1];
  $if_broadcast = $netconfig[2];
  `ifconfig $tap $tapip netmask $if_net broadcast $if_broadcast`;
  $ec = getec();
  printlog("Setting IP address: $tapip - $if_net - $if_broadcast", "$ec");

  # Check for existing rules.
  $rulecheck = `ip rule list | grep $tap | wc -l`;
  chomp($rulecheck);
  if ($rulecheck == 0) {
    $result = ipruleadd($tap, $tapip);
  } else {
    $result = deliprules($tap);
    $result = ipruleadd($tap, $tapip);
    $checktap = `$c_surfidsdir/scripts/checktap.pl $tap`;
    $ec = getec();
    printlog("Running: $c_surfidsdir/scripts/checktap.pl $tap", "$ec");
  }

  # Just to be sure, flush the routing table of the tap device.
  flushroutes($tap);
  $ec = getec();
  printlog("Flushing $tap routing table!", "$ec");

  # Calculate the network based on the tapip and the netmask.
  $network = getnetwork($tapip, $if_net);
  $ec = getec();
  printlog("Network: $network", "$ec");
  print LOG "[$ts - $tap - $ec] Network: $network\n";

  # Check if there are any routes present in the main routing table.
  $routecheck = `ip route list | grep $tap | wc -l`;
  chomp($routecheck);
  $ec = getec();
  printlog("IP routes present in main table: $routecheck", "$ec");

  if ($routecheck == 0) {
    # If none were present, add it. This needs to be done otherwise you'll get an error when adding the default gateway
    # for the tap device routing table.
    $result = addroute($network, $tap, $tapip, "main");
    $ec = getec();
    printlog("Adding route to table main", "$ec");
  }

  # Add default gateway to the routing table of the tap device.
  $result = adddefault($if_gw, $tap);
  $ec = getec();
  printlog("Adding default route to table $tap", "$ec");

  # At this point we can delete the route to the network from the main table as there is now a default gateway in
  # the routing table from the tap device.
  $result = delroute($network, $tap, $tapip, "main");
  $ec = getec();
  printlog("Deleting route from table main", "$ec");

  # Add the route to the network to the routing table of the tap device.
  $result = addroute($network, $tap, $tapip, $tap);
  $ec = getec();
  printlog("Adding route to table $tap", "$ec");
}

$count = 0;
$i = 0;
# Check if the tap device has an IP address.
while ($count == 0 && $i < $c_sql_dhcp_retries) {
  # First check if the tap device still exists, if not, it could not get an IP address with DHCP.
  $tapcheck = `ifconfig $tap`;
  if ($? != 0) {
    $count = 1;
    $ec = getec();
    printlog("The tap device was not present!", "$ec");
    printdblog($sensorid, 9);
    $err = 1;
    break;
  } else {
    $count = `ifconfig $tap | grep "inet addr:" | wc -l`;
    chomp($count);
  }
  $i++;
  if ($i == $c_sql_dhcp_retries) {
    printlog("The tap device could not get an IP address!", "Err");
    printdblog($sensorid, 10);
    $err = 1;
  }
  sleep 1;
}

if ($err == 0) {
  printlog("$tap device is up. Checking IP address.");

  # Get the IP address from the tap interface.
  $tap_ip = getifip($tap);
  $ec = getec();
  printlog("Tap IP address: $tap_ip", "$ec");

  # Connect to the database (dbh = DatabaseHandler or linkserver)
  $dbconn = connectdb();

  if ("$dbconn" ne "false") {
    # Update Tap info to the database for the current $sensor.
    $sql = "UPDATE sensors SET tap = '$tap', tapip = '$tap_ip', status = 1 WHERE keyname = '$sensor' AND remoteip = '$remoteip'";
    $er = $dbh->do($sql);
    printlog("Prepared query: $sql");
    printlog("Executed query: $er");
    printdblog($sensorid, 11);

    # Closing database connection.
    $dbh->disconnect;
  } else {
    printlog("No database connection!");
  }

  if ($c_enable_pof == 1) {
    system "p0f -d -i $tap -o /dev/null";
    printlog("Started p0f!");
  }

  if ($c_enable_arp == 1) {
    if ($arp == 1) {
      system("$c_surfidsdir/scripts/detectarp.pl $tap &");
      printlog("Started detectarp.pl!");
    }
  }
}

printlog("----------------finished sql.pl------------");

# Closing logfile filehandle.
close(LOG);
