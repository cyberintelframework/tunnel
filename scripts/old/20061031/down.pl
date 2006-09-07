#!/usr/bin/perl

###################################
#    Stop script for IDS server	  #
#           SURFnet IDS           #
#           Version 1.08          #
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

####################
# Modules used
####################
use DBI;
use Time::localtime;

####################
# Variables used
####################
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

####################
# Main script
####################

# Get tap device that's going down.
$if = $ARGV[0];

# Opening log file
open(LOG, ">> $logfile");

$ts = getts();
print LOG "[$ts - $if] Starting down.pl for $if \n";

# Connect to the database (dbh = DatabaseHandler or linkserver)
$dbh = DBI->connect($dsn, $pgsql_user, $pgsql_pass)
        or die $DBI::errstr;
$ts = getts();
print LOG "[$ts - $if] Connected to $pgsql_dbname with DSN: $dsn\n";
print LOG "[$ts - $if] Connect result: $dbh\n";

# Get the IP address configuration for the tap device from the database.
$sth = $dbh->prepare("SELECT s_tapip FROM sensors WHERE tap = '$if'");
$ts = getts();
print LOG "[$ts - $tap] Prepared query: SELECT s_tapip FROM sensors WHERE tap = '$if'\n";
$execute_result = $sth->execute();
$ts = getts();
print LOG "[$ts - $tap] Executed query: $execute_result\n";

@row = $sth->fetchrow_array;
$s_tapip = $row[0];
$ts = getts();
print LOG "[$ts - $tap] Query result: $s_tapip \n";

# s_tapip is empty or NULL for DHCP
if ($s_tapip == "NULL" || ($s_tapip == "")) {
  # Use DHCP
  $net_method = "dhcp";
} else {
  # Use static network configuration
  $net_method = "static";
}

$ts = getts();
print LOG "[$ts - $if] Network is using configuration: $net_method \n";

if ($net_method eq "dhcp") {
  # Kill dhclient3 (only for DHCP network configuration)
  $dhclient = `ps -ef | grep "dhclient3 -lf /var/lib/dhcp3/$if.leases" | grep -v grep`;
  chomp($dhclient);
  @dhclient = split(/ +/, $dhclient);
  $dhclient_pid = $dhclient[1];
  chomp($dhclient_pid);
  $kill_result = `kill $dhclient_pid`;
  $ts = getts();
  $ec = getec();
  print LOG "[$ts - $if - $ec] Killed dhclient3 with pid ($dhclient_pid)\n";

  # Delete .leases file
  `rm -f /var/lib/dhcp3/$if.leases`;
  $ts = getts();
  $ec = getec();
  print LOG "[$ts - $if - $ec] Deleted dhcp lease file /var/lib/dhcp3/$if.leases\n";
}

# Delete source based routing rule
$total_if_ip = `ip rule list | grep -i "$if" | cut -f2 -d " " | wc -l`;
chomp($total_if_ip);
$ts = getts();
$ec = getec();
print LOG "[$ts - $if - $ec] Retrieved routing rules: $total_if_ip\n";
for ($i=1; $i<=$total_if_ip; $i++) {
  # Get former ip address of tap device
  $if_ip = `ip rule list | grep -i "$if" | cut -f2 -d " " | tail -1`;
  chomp($if_ip);
  # Delete rule from ip address in table if
  `ip rule del from $if_ip table $if`;
  $ts = getts();
  $ec = getec();
  print LOG "[$ts - $if - $ec] Deleted ip rule: ip rule del from $if_ip table $if\n";
}

$remoteip = $ENV{REMOTE_HOST};
if ( ! $remoteip ) {
  # Prepare and execute sql query on database to retrieve remoteip.
  $sth = $dbh->prepare("SELECT remoteip FROM sensors WHERE tap = '$if'");
  $ts = getts();
  print LOG "[$ts - $if] Prepared query: SELECT remoteip FROM sensors WHERE tap = '$if'\n";
  $execute_result = $sth->execute();
  $ts = getts();
  print LOG "[$ts - $if] Executed query: $execute_result\n";

  # Get remote ip address of tap device ($if) from the query result.
  @row = $sth->fetchrow_array;
  $ts = getts();
  $remoteip = $row[0];
}
print LOG "[$ts - $if] Remoteip = $remoteip\n";

# Execute query to remove tap device information from database.
$execute_result = $dbh->do("UPDATE sensors SET tap = '', tapip = NULL WHERE tap = '$if'");
$ts = getts();
print LOG "[$ts - $if] Prepared query: UPDATE sensors SET tap = '', tapip = NULL WHERE tap = '$if'\n";
print LOG "[$ts - $if] Executed query: $execute_result\n";

# Delete route to connecting ip address of client via local gateway.
$sth = $dbh->prepare("SELECT Count(remoteip) FROM sensors WHERE remoteip = '$remoteip'");
$ts = getts();
print LOG "[$ts - $if] Prepared query: SELECT Count(remoteip) FROM sensors WHERE remoteip = '$remoteip'\n";
$execute_result = $sth->execute();
$ts = getts();
print LOG "[$ts - $if] Executed query: $execute_result\n";

# Get the count of remote ip addresses from the query result.
@row = $sth->fetchrow_array;
$ts = getts();
$count = $row[0];
print LOG "[$ts - $if] Query result: count = $count\n";
if ($count == 1) {
  `route del -host $remoteip`;
  $ts = getts();
  $ec = getec();
  print LOG "[$ts - $if - $ec] Deleted route: route del -host $remoteip\n";
}

# Flush the routing table of the tap device just to be sure.
`ip route flush table $if`;
$ts = getts();
$ec = getec();
print LOG "[$ts - $if - $ec] Flushing routing table for $if: ip route flush table $if\n";

# Closing database connection.
$dbh = "";
#$dbh->disconnect;

$ts = getts();
print LOG "-------------finished down.pl-----------\n";

# Closing log filehandle.
close(LOG);
