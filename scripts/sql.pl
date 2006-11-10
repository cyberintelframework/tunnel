#!/usr/bin/perl -w

###################################
# SQL script for IDS server       #
# SURFnet IDS                     #
# Version 1.04.01                 #
# 07-11-2006                      #
# Jan van Lith & Kees Trippelvitz #
# Modified by Peter Arts          #
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
# 1.04.01 Rereleased as 1.04.01
# 1.02.03 Added vlan support 
# 1.02.02 Added ARP monitoring support
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
$sql = "SELECT netconf, netconfdetail, tapip, arp FROM sensors WHERE keyname = '$sensor' AND remoteip = '$remoteip'";
$sth = $dbh->prepare($sql);
printlog("Prepared query: $sql");
$er = $sth->execute();
printlog("Executed query: $er");

@row = $sth->fetchrow_array;
$netconf = $row[0];
$netconfdetail = $row[1];
$tapip = $row[2];
$sensor_arp = $row[3];

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
  printlog("Network config method: static");

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
#    $addrule = `ip rule add from $tapip table $tap`;
#    $ts = getts();
#    $ec = getec();
#    print LOG "[$ts - $tap - $ec] ip rule add from $tapip table $tap\n";
  } else {
    $result = deliprules($tap);
#    # Get the old ip rule and remove it.
#    $oldip = `ip rule list | grep $tap | awk '{print $3}'`;
#    $ts = getts();
#    $ec = getec();
#    print LOG "[$ts - $tap - $ec] Old ip: $oldip\n";

#    $remove = `ip rule del from $oldip table $tap`;
#    $ts = getts();
#    $ec = getec();
#    print LOG "[$ts - $tap - $ec] ip rule del from $oldip table $tap\n";

    $result = ipruleadd($tap, $tapip);
#    $addrule = `ip rule add from $tapip table $tap`;
#    $ts = getts();
#    $ec = getec();
#    print LOG "[$ts - $tap - $ec] ip rule add from $tapip table $tap\n";

    $checktap = `$surfidsdir/scripts/checktap.pl $tap`;
    $ec = getec();
    printlog("Running: $surfidsdir/scripts/checktap.pl $tap", "$ec");
  }

  # Just to be sure, flush the routing table of the tap device.
  $flushtap = `ip route flush table $tap`;
  $ts = getts();
  $ec = getec();
  print LOG "[$ts - $tap - $ec] ip route flush table $tap\n";

  # Calculate the network based on the tapip and the netmask.
  $network = `$surfidsdir/scripts/ipcalc $tapip $if_net | grep -i Network`;
  @network_ar = split(/ +/,$network);
  $network = $network_ar[1];
  $ts = getts();
  $ec = getec();
  print LOG "[$ts - $tap - $ec] Network: $network\n";

  # Check if there are any routes present in the main routing table.
  $routecheck = `ip route list | grep $tap | wc -l`;
  chomp($routecheck);
  $ts = getts();
  $ec = getec();
  print LOG "[$ts - $tap - $ec] IP routes present in main table: $routecheck\n";

  if ($routecheck == 0) {
    # If none were present, add it. This needs to be done otherwise you'll get an error when adding the default gateway
    # for the tap device routing table.
    $routeadd = `ip route add $network dev $tap src $tapip table main`;
    $ts = getts();
    $ec = getec();
    print LOG "[$ts - $tap - $ec] ip route add $network dev $tap src $tapip table main\n";
  }

  # Add default gateway to the routing table of the tap device.
  $adddefault = `ip route add default via $if_gw table $tap`;
  $ts = getts();
  $ec = getec();
  print LOG "[$ts - $tap - $ec] ip route add default via $if_gw table $tap\n";

  # At this point we can delete the route to the network from the main table as there is now a default gateway in
  # the routing table from the tap device.
  $routedel=`ip route del $network dev $tap src $tapip table main`;
  $ts = getts();
  $ec = getec();
  print LOG "[$ts - $tap - $ec] ip route del $network dev $tap src $tapip table main\n";

  # Add the route to the network to the routing table of the tap device.
  $routeadd=`ip route add $network dev $tap src $tapip table $tap`;
  $ts = getts();
  $ec = getec();
  print LOG "[$ts - $tap - $ec] ip route add $network dev $tap src $tapip table $tap\n";
}

$count = 0;
$i = 0;
# Check if the tap device has an IP address.
while ($count == 0 && $i < $sql_dhcp_retries) {
  # First check if the tap device still exists, if not, it could not get an IP address with DHCP.
  $tapcheck = `ifconfig $tap`;
  if ($? != 0) {
    $count = 1;
    $ts = getts();
    $ec = getec();
    print LOG "[$ts - $tap - $ec] Error: The tap device was not present.\n";
    $err = 1;
    break;
  } else {
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
  $execute_result = $dbh->do("UPDATE sensors SET tap = '$tap', tapip = '$tap_ip', status = 1 WHERE keyname = '$sensor' AND remoteip = '$remoteip'");
  $ts = getts();
  print LOG "[$ts - $tap] Prepared query: UPDATE sensors SET tap = '$tap', tapip = '$tap_ip', status = 1 WHERE keyname = '$sensor' AND remoteip = '$remoteip'\n";
  print LOG "[$ts - $tap] Executed query: $execute_result\n";

  # Closing database connection.
  $dbh->disconnect;

  if ($enable_pof == 1) {
    system "p0f -d -i $tap -o /dev/null";
    print LOG "[$ts - $tap] Started p0f script\n";
  }
  if ($enable_tcpmonitor == 1 && $sensor_arp == 1) {
    system "$surfidsdir/scripts/pcap.pl $tap &";
    print LOG "[$ts - $tap] Started pcap.pl script\n";
  }
}

print LOG "----------------finished sql.pl------------\n";

# Closing logfile filehandle.
close(LOG);
