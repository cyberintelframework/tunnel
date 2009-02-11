#!/usr/bin/perl -w

####################################
# Checktap script                  #
# SURFids 2.10                     #
# Changeset 001                    #
# 18-03-2008                       #
# Jan van Lith & Kees Trippelvitz  #
####################################

#####################
# Changelog:
# 001 Initial release
#####################

##################
# Modules used
##################
use DBI;
use Time::localtime qw(localtime);

##################
# Variables used
##################
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
  $logfile = "$c_surfidsdir/log/$day$month$year/$logfile";
} else {
  $logfile = "$c_surfidsdir/log/$logfile";
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
$dbconn = dbconnect();

if ("$dbconn" ne "false") {
  # Prepare and execute sql query on database to retrieve tapip.
  $sql = "SELECT tapip, netconf FROM sensors WHERE tap = '$tap'";
  $sth = $dbh->prepare($sql);
  printlog("Prepared query: $sql");
  $er = $sth->execute();
  printlog("Executed query: $er");

  # Get the tap ip address of tap device ($tap) from the query result.
  @row = $sth->fetchrow_array;
  $db_tapip = $row[0];
  $db_netconf = $row[1];
  chomp($db_tapip);
  chomp($db_netconf);
  printlog("DB Tap IP address: $db_tapip");
  printlog("DB netconf: $db_netconf");

  # Get the actual IP address of the tap device.
  $tapip = getifip($tap);
  chomp($tapip);
  printlog("IP address of $tap: $tapip");

  if (("$db_netconf" eq "dhcp" || "$db_netconf" eq "vland") && "$tapip" ne "false") {
    # If the tap IP addresses don't match, fix it.
    if ("$tapip" ne "$db_tapip") {
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
