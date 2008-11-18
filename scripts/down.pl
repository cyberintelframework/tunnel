#!/usr/bin/perl

###################################
# Stop script for IDS server	  #
# SURFids 2.00.04                 #
# Changeset 001                   #
# 30-05-2008                      #
# Jan van Lith & Kees Trippelvitz #
###################################

#####################
# Changelog:
# 001 version 2.00 (added logmessages support)
#####################

####################
# Modules used
####################
use DBI;
use Time::localtime qw(localtime);

####################
# Variables used
####################
# Get tap device that's going down.
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
