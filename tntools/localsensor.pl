#!/usr/bin/perl

####################################
# Local sensor script              #
# SURFids 3.00                     #
# Changeset 005                    #
# 26-06-2009                       #
# Jan van Lith & Kees Trippelvitz  #
####################################

#####################
# Changelog:
# 005 Added -h switch
# 004 Fixed to comply with new DB structure
# 003 Completely redone the script
# 002 Added usage info on failure
# 001 Initial version
#####################

##################
# Modules used
##################
use DBI;
use Time::localtime qw(localtime);
use Getopt::Std;

##################
# Handling opts
##################
sub usage() {
    print "Usage: ./localsensor.pl -i <interface name> -s <sensor name> -o <organisation name>\n";
    print "Usage: ./localsensor.pl -p <ip address> -m <mac address> -s <sensor name> -o <organisation name>\n";
    print "\n";
    print "   -i <interface name>                   Interface that has to be added as a sensor\n";
    print "   -p <ip address>                       IP address of the sensor\n";
    print "   -m <mac address>                      MAC address of the sensor, defaults to 00:00:00:00:00:00\n";
    print "   -s <sensor name>                      Name of the sensor, defaults to Nepenthes\n";
    print "   -o <organisation name>                Organisation name, defaults to LOCAL\n";
    print "   -h                                    This help message\n";
    print "\n";
    print "Example: ./localsensor.pl -i eth0 -s mySensor -o SURFnet\n";
    print "Example: ./localsensor.pl -p 192.168.10.12 -m 00:11:22:33:44:55 -s mySensor -o SURFnet\n";
    print "\n";
}

getopts('i:p:m:s:o:h', \%opts);

$sensor = $opts{"s"};
$if = $opts{"i"};
$org = $opts{"o"};
$ip = $opts{"p"};
$mac = $opts{"m"};
if ($opts{"h"}) {
  usage();
  exit 0;
}

##################
# Configuration
##################
if (-r "/etc/surfnetids/surfnetids-log.conf") {
  do "/etc/surfnetids/surfnetids-log.conf";
} else {
  # The root directory for the SURFids files (no trailing forward slash).
  $c_surfidsdir = "/opt/surfnetids";

  # User info for the logging user in the postgresql database
  $c_pgsql_pass = "enter_database_password_here";
  $c_pgsql_user = "idslog";

  # Postgresql database info
  $c_pgsql_host = "enter_database_host_here";
  $c_pgsql_dbname = "idsserver";

  # The port number where the postgresql database is running on.
  $c_pgsql_port = "5432";

  # Connection string, default should be correct.
  $c_dsn = "DBI:Pg:dbname=$c_pgsql_dbname;host=$c_pgsql_host;port=$c_pgsql_port";
}

##################
# Functions
##################
if (-e "logfunctions.inc.pl") {
  require "logfunctions.inc.pl";
} elsif (-e "$c_surfidsdir/logtools/logfunctions.inc.pl") {
  require "$c_surfidsdir/logtools/logfunctions.inc.pl";
} else {
  require "$c_surfidsdir/scripts/logfunctions.inc.pl";
}

##################
# Main script
##################

if ($if eq "" && $ip eq "") {
  usage();
  exit;
}

if ($sensor eq "") {
  $sensor = "Nepenthes";
}

if ($org eq "") {
  $org = "LOCAL";
}

if ($if ne "") {
  $ifip = getifip($if);
  if ($ifip eq "false") {
    print "Could not retrieve IP address for interface $if\n";
    exit;
  }
  $ifmac = getifmac($if);
  if ($ifmac eq "false") {
    print "Could not retrieve MAC address for interface $if\n";
    exit;
  }
} else {
  $ifip = $ip;
  if ($mac eq "") {
    $ifmac = "00:00:00:00:00:00";
  } else {
    $ifmac = $mac;
  }
}

$ts = time;

dbconnect();

# First check if the IP address already exists in the database
$chk = dbnumrows("SELECT id FROM sensors WHERE tapip = '$ifip'");
if ($chk > 0) {
  print "Sensor with IP address $ifip already exists\n";
  exit;
}

# First check if the sensor name already exists in the database
$chk = dbnumrows("SELECT id FROM sensors WHERE keyname = '$sensor'");
if ($chk > 0) {
  print "Sensor with name $sensor already exists\n";
  exit;
}

#$sth = dbquery("SELECT value FROM serverinfo WHERE name = 'updaterev'");
#@row = $sth->fetchrow_array;
#$rev = $row[0];
#if ($rev eq "") {
#  $rev = 0;
#}
$rev = 0;

# First check if the organisation already exists in the database
$chk = dbnumrows("SELECT id FROM organisations WHERE organisation = '$org'");
if ($chk > 0) {
  $sth = dbquery("SELECT id FROM organisations WHERE organisation = '$org'");
  @row = $sth->fetchrow_array;
  $orgid = $row[0];
} else {
  $sth = dbquery("INSERT INTO organisations (organisation) VALUES ('$org')");

  $sth = dbquery("SELECT id FROM organisations WHERE organisation = '$org'");
  @row = $sth->fetchrow_array;
  $orgid = $row[0];
}

print "Sensor: $sensor\n";
print "IP address: $ifip\n";
print "MAC address: $ifmac\n";
print "Organisation: $org\n";
print "Org ID: $orgid\n";
print "\n";

$chk = "none";
while ($chk !~ /^(n|N|y|Y)$/) {
  $chk = prompt("Add this sensor? [yN]", "N");
}

if ($chk =~ /^(y|Y)/) {
  print "Adding sensor to the database!\n";
  if ($orgid ne "") {
    $sql = "INSERT INTO sensor_details (keyname, remoteip, localip, lastupdate, sensormac, permanent) ";
    $sql .= " VALUES ('$sensor', '$ifip', '$ifip', $ts, '$ifmac', 1)";
    $chk1 = dbnumrows($sql);

    $sql = "INSERT INTO sensors (keyname, laststart, status, uptime, tap, tapip, mac, organisation) ";
    $sql .= " VALUES ('$sensor', $ts, 1, 0, '$if', '$ifip', '$ifmac', $orgid)";
    $chk2 = dbnumrows($sql);
    $chk = $chk1 + $chk2;
    if ($chk != 0) {
      print "Sensor successfully added to the database!\n";
    } else {
      print "Failed to add sensor!\n";
    }
  }
} else {
  print "Not adding sensor!\n";
}
