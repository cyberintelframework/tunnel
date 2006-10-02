#!/usr/bin/perl

###################################
#     SQL script for IDS server   #
#           SURFnet IDS           #
#           Version 1.09          #
#            31-01-2006           #
# Jan van Lith & Kees Trippelvitz #
#     Modified by Peter Arts      #
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
print LOG "[$ts - $tap] Starting sql.pl for $sensor on $tap \n";

# Connect to the database (dbh = DatabaseHandler or linkserver)
$dbh = DBI->connect($dsn, $pgsql_user, $pgsql_pass)
      or die $DBI::errstr;
$ts = getts();
print LOG "[$ts - $tap] Connected to $pgsql_dbname with DSN: $dsn\n";
print LOG "[$ts - $tap] Connect result: $dbh\n";

# Get sensor id
$sth = $dbh->prepare("SELECT id FROM sensors WHERE keyname = '$sensor'");
$ts = getts();
print LOG "[$ts - $tap] Prepared query: SELECT id FROM sensors WHERE keyname = '$sensor'\n";
$execute_result = $sth->execute();
$ts = getts();
print LOG "[$ts - $tap] Executed query: $execute_result\n";

@row = $sth->fetchrow_array;
$sensor_id = $row[0];
print LOG "[$ts - $tap] Found sensor_id: $sensor_id \n";

# Get the IP address configuration for the tap device from the database.
$sth = $dbh->prepare("
SELECT static_ip, static_netmask, static_gateway, static_broadcast, id
FROM   netconfig
WHERE  sensor_id = '$sensor_id'
  AND  used = 'f'
");
#  AND  static_ip NOT IN
#	(SELECT ip FROM tap WHERE sensor_id = '$sensor_id')
#");
$ts = getts();
print LOG "[$ts - $tap] Prepared query: SELECT static_ip, static_netmask, static_gateway, static_broadcast FROM netconfig WHERE sensor_id = '$sensor_id' AND used = 'f' \n";
$execute_result = $sth->execute();
$ts = getts();
print LOG "[$ts - $tap] Executed query: $execute_result\n";

@row = $sth->fetchrow_array;
$ts = getts();
$if_ip = $row[0];
$netconfig_id = $row[4];
print LOG "[$ts - $tap] Result: $if_ip (empty=dhcp)\n";

# Set used = TRUE in table netconfig to prevent ip conflicts
$execute_result = $dbh->do("UPDATE netconfig SET used = 't' WHERE id = '$netconfig_id'");
$ts = getts();
print LOG "[$ts - $tap] Prepared query: UPDATE netconfig SET used = 't' WHERE id = '$netconfig_id'\n";
print LOG "[$ts - $tap] Executed query: $execute_result\n";

# Closing database connection.
$dbh->disconnect;

# Sleep till tunnel is fully ready 
sleep 2;

# $if_ip eq "" => use dhcp
if ($if_ip eq "") {
  # Tap configuration not set or no more ip addresses to use: assume dhcp
  $net_method = "dhcp";
} else {
  # Use static network configuration
  $net_method = "static";
}

$ts = getts();
$ec = getec();
print LOG "[$ts - $tap - $ec] Network is using method: $net_method \n";

if ($net_method eq "dhcp") {
  # Get dhcp from remote network without setting of gateway, dns and resolv.conf
  `dhclient3 -lf /var/lib/dhcp3/$tap.leases -sf $surfidsdir/scripts/surfnetids-dhclient $tap`;
  $ts = getts();
  $ec = getec();
  print LOG "[$ts - $tap - $ec] Starting dhclient3 in sql.pl: dhclient3 -sf /etc/dhcp3/dhtest-script -lf /var/lib/dhcp3/$tap.leases $tap\n";
} else { 
  # Set static network configuration without gateway, dns and resolv.conf
  # Format of netconfig: @row([0]=>IP, [1]=>netmask, [2]=>gateway, [3]=>broadcast)
  $if_net = $row[1];
  $if_gw = $row[2];
  $if_broadcast = $row[3];
  `ifconfig $tap $if_ip netmask $if_net broadcast $if_broadcast`;
  $ts = getts();
  $ec = getec();
  print LOG "[$ts - $tap - $ec] Setting IP address: $if_ip, netmask: $if_net and broadcast: $if_broadcast \n";

  # Set tablename exactly to tap device
  $tablename = $tap;

  # Set routes in routing table of tap device to enable source-based routing
  `ip route add default via $if_gw table $tablename`;
  $ts = getts();
  $ec = getec();
  print LOG "[$ts - $tap - $ec] Executed: ip route add default via $if_gw table $tablename\n";

  # Delete all existing rules from table $tap
  $total_if_ip = `ip rule list | grep -i "$tap" | cut -f2 -d " " | wc -l`;
  chomp($total_if_ip);
  $ts = getts();
  print LOG "[$ts - $tap] Retrieved total_if_ip: $total_if_ip\n";
  for ($i=1; $i<=$total_if_ip; $i++)
  {
    # Get former ip address of tap device
    $if_ip=`ip rule list | grep -i "$tap" | cut -f2 -d " " | tail -1`;
    # Delete rule from ip address in table if
    `ip rule del from $if_ip table $tap`;
    $ts = getts();
    pring LOG "[$ts - $cat] Deleted ip rule: ip rule del from $if_ip table $tap\n";
  }

  # Add new rule to enable source-based routing
  $rulecheck = `ip rule list | grep $cat | wc -l`;
  if ( $rulecheck == 0) {
    `ip rule add from $if_ip table $tablename`;
    $ts = getts();
    $ec = getec();
    print LOG "[$ts - $cat - $ec] Added new rule: ip rule add from $if_ip table $tablename\n";
  }
  else {
    print LOG "[$ts - $cat] Rule already exists.\n";
  }

  #$if_net = `ip route list | grep $tap | awk '{print $1}'`;
  $if_net = `ip route list | grep $tap`;
  @if_net_ar = split(/ +/, $if_net);
  $if_net = $if_net_ar[0];
  chomp($if_net);
  print LOG "Found if_net: $if_net \n";

  # Delete route to remote network in "main" routing table
  `ip route del $if_net dev $tap src $if_ip table main`;
  $ts = getts();
  $ec = getec();
  print LOG "[$ts - $cat - $ec] Deleted route to remote network: ip route del $if_net dev $tap src $if_ip table main\n";

  # Add route to remote network in the tap table.
  `ip route add $if_net dev $tap src $if_ip table $tablename`;
  $ts = getts();
  $ec = getec();
  print LOG "[$ts - $tap - $ec] Added route to remote network: ip route add $if_net dev $tap src $if_ip table $tablename\n";
}

sleep 1;

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
    $ts - getts();
    $ec = getec();
    print LOG "[$ts - $tap - $ec] Error: The tap device could not get an IP address (after $i retries).\n";
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

  # Get mac
  $mac = `ifconfig $tap | grep HWaddr`;
  @mac_ar = split(/ +/, $mac);
  $mac = $mac_ar[4];
  # Get mac_id from database
  $sth = $dbh->prepare("SELECT id FROM mac WHERE mac = '$mac' AND sensor_id = '$sensor_id'");
  $execute_result = $sth->execute();
  $ts = getts();
  print LOG "[$ts - $tap] Prepared query: SELECT id FROM mac WHERE mac = '$mac' AND sensor_id = '$sensor_id'\n";
  print LOG "[$ts - $tap] Executed query: $execute_result\n";
  @row = $sth->fetchrow_array;
  $mac_id = $row[0];

  # Update Tap info to the database for the current $sensor.
  $sth = $dbh->prepare("INSERT INTO tap (dev, ip, sensor_id, mac_id) VALUES ('$tap', '$tap_ip', '$sensor_id', '$mac_id')") or print LOG "Can't prepare query, DB error: $dbh->errstr";
  $execute_result = $sth->execute() or print LOG "Can't execute query, DB error: $dbh->err_str";
  $ts = getts();
  print LOG "[$ts - $tap] Prepared query: INSERT INTO tap (dev, ip, sensor_id, mac_id) VALUES ('$tap', '$tap_ip', '$sensor_id', '$mac_id')\n";
  print LOG "[$ts - $tap] Executed query: $execute_result\n";

  # Closing database connection.
  $dbh->disconnect;
}

print LOG "----------------finished sql.pl for $tap------------\n";

# Closing logfile filehandle.
close(LOG);
