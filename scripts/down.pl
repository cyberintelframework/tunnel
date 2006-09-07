#!/usr/bin/perl -w

###################################
# Stop script for IDS server	  #
# SURFnet IDS                     #
# Version 1.02.02                 #
# 10-07-2006                      #
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

####################
# Main script
####################

# Opening log file
open(LOG, ">> $logfile");

$ts = getts();
print LOG "[$ts - $tap] Starting down.pl\n";

#print LOG "======================================================\n";
#foreach $key (sort keys(%ENV)) {
#  print LOG "$key = $ENV{$key}\n";
#}
#print LOG "======================================================\n";

# Connect to the database (dbh = DatabaseHandler or linkserver)
$dbh = DBI->connect($dsn, $pgsql_user, $pgsql_pass);
$ts = getts();
print LOG "[$ts - $tap] Connecting to $pgsql_dbname with DSN: $dsn\n";
if ($dbh ne "") {
  print LOG "[$ts - $tap] Connect result: Ok\n";
}
else {
  print LOG "[$ts - $tap - Err] Connect result: failed\n";
  $pgerr = $DBI::errstr;
  chomp($pgerr);
  print LOG "[$ts - $tap - Err] Error message: $pgerr\n";
}

# Reset status
$sth = $dbh->prepare("UPDATE sensors SET status = 0 WHERE tap = '$tap'");
$ts = getts();
print LOG "[$ts - $tap] Prepared query: UPDATE sensors SET status = 0 WHERE tap = '$tap'\n";
$execute_result = $sth->execute();
$ts = getts();
print LOG "[$ts - $tap] Executed query: $execute_result\n";

# Kill dhclient3
$dhclient = `ps -ef | grep "dhclient3 -lf /var/lib/dhcp3/$tap.leases" | grep -v grep`;
chomp($dhclient);
@dhclient = split(/ +/, $dhclient);
$dhclient_pid = $dhclient[1];
chomp($dhclient_pid);
$kill_result = `kill $dhclient_pid`;
$ts = getts();
$ec = getec();
print LOG "[$ts - $tap - $ec] Killed dhclient3 with pid ($dhclient_pid)\n";

# Delete .leases file
`rm -f /var/lib/dhcp3/$tap.leases`;
$ts = getts();
$ec = getec();
print LOG "[$ts - $tap - $ec] Deleted dhcp lease file /var/lib/dhcp3/$tap.leases\n";

# Delete source based routing rule
$total_if_ip = `ip rule list | grep -i "$tap" | cut -f2 -d " " | wc -l`;
chomp($total_if_ip);
$ts = getts();
$ec = getec();
print LOG "[$ts - $tap - $ec] Retrieved routing rules: $total_if_ip\n";
for ($i=1; $i<=$total_if_ip; $i++) {
  # Get former ip address of tap device
  $if_ip = `ip rule list | grep -i "$tap" | cut -f2 -d " " | tail -1`;
  chomp($if_ip);
  # Delete rule from ip address in table if
  `ip rule del from $if_ip table $tap`;
  $ts = getts();
  $ec = getec();
  print LOG "[$ts - $tap - $ec] Deleted ip rule: ip rule del from $if_ip table $tap\n";
}

if ($dbh ne "") {
  # Get the remote IP address.
  $remoteip = $ENV{REMOTE_HOST};
  if ( ! $remoteip ) {
    # Remote IP address was not set in the environment variables. Get it from the database.
    # Prepare and execute sql query on database to retrieve remoteip.
    $sth = $dbh->prepare("SELECT remoteip FROM sensors WHERE tap = '$tap'");
    $ts = getts();
    print LOG "[$ts - $tap] Prepared query: SELECT remoteip FROM sensors WHERE tap = '$tap'\n";
    $execute_result = $sth->execute();
    $ts = getts();
    print LOG "[$ts - $tap] Executed query: $execute_result\n";

    # Get remote ip address of tap device ($tap) from the query result.
    @row = $sth->fetchrow_array;
    $ts = getts();
    $remoteip = $row[0];
  }
  print LOG "[$ts - $tap] Remoteip = $remoteip\n";

  # Get the network config method. (Static / DHCP)
  $sth = $dbh->prepare("SELECT netconf FROM sensors WHERE tap = '$tap'");
  $ts = getts();
  print LOG "[$ts - $tap] Prepared query: SELECT netconf FROM sensors WHERE tap = '$tap'\n";
  $execute_result = $sth->execute();
  $ts = getts();
  print LOG "[$ts - $tap] Executed query: $execute_result\n";

  @row = $sth->fetchrow_array;
  $ts = getts();
  $netconf = $row[0];

  if ($netconf eq "dhcp" || $netconf eq "") {
    # Network configuration method was DHCP. We delete both the tap device and address from the database.
    print LOG "[$ts - $tap] Network config method: DHCP\n";
    # Execute query to remove tap device information from database.
    $execute_result = $dbh->do("UPDATE sensors SET tap = '', tapip = NULL WHERE tap = '$tap'");
    $ts = getts();
    print LOG "[$ts - $tap] Prepared query: UPDATE sensors SET tap = '', tapip = NULL WHERE tap = '$tap'\n";
    print LOG "[$ts - $tap] Executed query: $execute_result\n";
  }
  else {
    # Network configuration method was Static. We don't delete the tap IP address from the database.
    print LOG "[$ts - $tap] Network config method: static\n";
    # Execute query to remove tap device information from database.
    $execute_result = $dbh->do("UPDATE sensors SET tap = '' WHERE tap = '$tap'");
    $ts = getts();
    print LOG "[$ts - $tap] Prepared query: UPDATE sensors SET tap = '' WHERE tap = '$tap'\n";
    print LOG "[$ts - $tap] Executed query: $execute_result\n";
  }

  # Delete route to connecting ip address of client via local gateway.
  $sth = $dbh->prepare("SELECT COUNT(remoteip) FROM sensors WHERE remoteip = '$remoteip'");
  $ts = getts();
  print LOG "[$ts - $tap] Prepared query: SELECT COUNT(remoteip) FROM sensors WHERE remoteip = '$remoteip'\n";
  $execute_result = $sth->execute();
  $ts = getts();
  print LOG "[$ts - $tap] Executed query: $execute_result\n";

  # Get the count of remote ip addresses from the query result.
  @row = $sth->fetchrow_array;
  $ts = getts();
  $count = $row[0];
  print LOG "[$ts - $tap] Query result: count = $count\n";
  if ($count == 1) {
    # There is only 1 remoteip address in the database so we can delete the static route towards this IP.
    `route del -host $remoteip`;
    $ts = getts();
    $ec = getec();
    print LOG "[$ts - $tap - $ec] Deleted route: route del -host $remoteip\n";
  }
}
else {
  $remoteip = $ENV{REMOTE_HOST};
  `route del -host $remoteip`;
  $ts = getts();
  $ec = getec();
  print LOG "[$ts - $tap - $ec] Deleted route: route del -host $remoteip\n";
}



# Flush the routing table of the tap device just to be sure.
`ip route flush table $tap`;
$ts = getts();
$ec = getec();
print LOG "[$ts - $tap - $ec] Flushing routing table for $tap: ip route flush table $tap\n";

# Closing database connection.
$dbh = "";

$ts = getts();
print LOG "-------------finished down.pl-----------\n";

# Closing log filehandle.
close(LOG);
