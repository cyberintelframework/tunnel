#!/usr/bin/perl

###################################
#   Setmac script for IDS server  #
#           SURFnet IDS           #
#           Version 1.04          #
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

# Get tap device that's coming up.
$tap = $ENV{dev};

# Get sensor name.
$sensor = $ENV{common_name};

# Opening log file
open(LOG, ">> $logfile");

$ts = getts();
print LOG "[$ts - $tap] Starting setmac.pl\n";

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

# Check for tap existance.
`ifconfig $tap`;

if ($? == 0) {

  $ec = getec();
  print LOG "[$ts - $tap - $ec] Tap device exists.\n";

  # Get a mac address for the sensor from the database.
  $sth = $dbh->prepare("
  SELECT mac, id 
  FROM   mac 
  WHERE  sensor_id = '$sensor_id'
    AND  used = 'f'
    AND  id NOT IN 
   	 (SELECT mac_id 
	  FROM   tap
	  WHERE sensor_id = '$sensor_id')
  ");

  $ts = getts();
  print LOG "[$ts - $tap] Prepared query: SELECT mac FROM mac WHERE sensor_id = '$sensor_id' AND used = 'f' AND id NOT IN (SELECT mac_id FROM tap WHERE sensor_id = '$sensor_id')\n";
  $execute_result = $sth->execute();
  $ts = getts();
  print LOG "[$ts - $tap] Executed query: $execute_result\n";

  @row = $sth->fetchrow_array;
  $ts = getts();
  $mac = $row[0];
  print LOG "[$ts - $tap] Found mac address: |$mac| (empty is new)\n";
  if ($mac eq "") {
    # If no mac address is present in the database, add the generated one from OpenVPN to the database.
    print LOG "[$ts - $tap] No more MAC addresses in mac table for $sensor.\n";
    $mac = `ifconfig $tap | grep HWaddr`;
    @mac_ar = split(/ +/, $mac);
    $mac = $mac_ar[4];
    $ts = getts();
    $ec = getec();
    print LOG "[$ts - $tap - $ec] New MAC address: $mac.\n";
    $sth = $dbh->prepare("INSERT INTO mac (mac, sensor_id, used) VALUES ('$mac', '$sensor_id', 't')") or print LOG "Can't prepare query: " .  $sth->errstr . " \n"; 
    $execute_result = $sth->execute() or print LOG "Can't execute query: " . $sth->errstr . " \n";
    $ts = getts();
    print LOG "[$ts - $tap] Prepared query: INSERT INTO mac (mac, sensor_id) VALUES ('$mac', '$sensor_id')\n";
    print LOG "[$ts - $tap] Executed query: $execute_result\n";
  }
  else {
    $mac_id = $row[1];
    # MAC address is present in the database
    # Update the mac table
    $execute_result = $dbh->do("UPDATE mac SET used = 't' WHERE id = '$mac_id'");
    $ts = getts();
    print LOG "[$ts - $tap] Prepared query: UPDATE mac SET used = 't' WHERE id = '$mac_id'\n";
    print LOG "[$ts - $tap] Executed query: $execute_result\n";

    # Update the interface with the new mac.
    print LOG "[$ts - $tap] MAC address already known.\n";
    `ifconfig $tap hw ether $mac`;
    $ts = getts();
    $ec = getec();
    print LOG "[$ts - $tap - $ec] MAC address of $tap set to $mac.\n";
  }

  # Wait for up.pl to be ready
  #$wait = 1;
  #while ($wait != 0) {
  #  $test = `ps -ef | grep 'up.pl $tap' | grep -v 'grep' | grep -v 'ps'`;
  #  print LOG "TEST: $test\n";
  #  $test2 = `ps -ef`;
  #  print LOG "TEST2: $test2\n";
  #  $wait = `ps -ef | grep 'up.pl $tap' | grep -v 'grep' | grep -v 'ps' | wc -l`;
  #  chomp($wait);
  #  sleep 1;
  #  $ts = getts();
  #  $ec = getec();
  #  print LOG "[$ts - $tap - $ec] Waiting for up.pl to be ready\n";
  #}
  #$ts = getts();
  #$ec = getec();
  #print LOG "[$ts - $tap - $ec] Script up.pl finished \n";

  # Sleep till tunnel is fully ready and then get dhcp from remote network without setting of gateway, dns and resolv.conf
  #sleep 2;
  #`dhclient3 -lf /var/lib/dhcp3/$tap.leases -sf $surfidsdir/scripts/surfnetids-dhclient $tap`;
  #$ts = getts();
  #$ec = getec();
  #print LOG "[$ts - $tap - $ec] Starting dhclient3: dhclient3 -sf /etc/dhcp3/dhtest-script -lf /var/lib/dhcp3/$tap.leases $tap\n";
  sleep 1;

  # Start the sql.pl script to update all tap device information to the database.
  system "$surfidsdir/scripts/sql.pl $tap $sensor &";
  print LOG "[$ts - $tap] Started sql script: $surfidsdir/scripts/sql.pl $tap $sensor\n";

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
