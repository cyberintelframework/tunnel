#!/usr/bin/perl -w

####################################
# Checktap script                  #
# SURFids 3.00                     #
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

##################
# Main script
##################

# Get the tap device.
$tap = $ARGV[0];

# Connect to the database (dbh = DatabaseHandler or linkserver)
$dbconn = dbconnect();

if ("$dbconn" ne "false") {
  # Prepare and execute sql query on database to retrieve tapip.
  $sql = "SELECT tapip, netconf FROM sensors WHERE tap = '$tap'";
  $sth = $dbh->prepare($sql);
  $er = $sth->execute();

  # Get the tap ip address of tap device ($tap) from the query result.
  @row = $sth->fetchrow_array;
  $db_tapip = $row[0];
  $db_netconf = $row[1];
  chomp($db_tapip);
  chomp($db_netconf);

  # Get the actual IP address of the tap device.
  $tapip = getifip($tap);
  chomp($tapip);

  if (("$db_netconf" eq "dhcp" || "$db_netconf" eq "vland") && "$tapip" ne "false") {
    # If the tap IP addresses don't match, fix it.
    if ("$tapip" ne "$db_tapip") {
      $sql = "UPDATE sensors SET tapip = '$tapip' WHERE tap = '$tap'";
      $er = $dbh->do($sql);
    }
  }

  # Closing database connection.
  $dbh = "";
}
