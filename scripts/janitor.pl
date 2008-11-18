#!/usr/bin/perl

#########################################
# Janitor (tunnel maintenance)          #
# SURFids 2.00.04                       #
# Changeset 001                         #
# 22-05-2008                            #
# Jan van Lith & Kees Trippelvitz       #
#########################################

#####################
# Changelog:
# 001 initial release
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
# Connect to the database (dbh = DatabaseHandler or linkserver)
$dbconn = connectdb();

$verbose = 0;
if ("$ARGV[0]" eq "-v") {
  $verbose = 1;
}

# Cleaning up sensor logs
$ts = time();
$ts = $ts - (60 * 60 * 24 * 7);
$sql = "DELETE FROM sensors_log USING logmessages WHERE sensors_log.timestamp < $ts AND sensors_log.logid = logmessages.id AND logmessages.type < 30";
$ec = $dbh->do($sql);

# Updating server repository version number of the sensor scripts
if (-r "$c_surfidsdir/svnroot/updates/db/current") {
  $server_rev = `cat $c_surfidsdir/svnroot/updates/db/current | awk '{print \$1}'`;
  chomp($server_rev);

  $sql_getrev = "SELECT value FROM serverinfo WHERE name = 'updaterev'";
  $sth_getrev = $dbh->prepare($sql_getrev);
  $sth_getrev->execute();

  @row = $sth_getrev->fetchrow_array;
  $server_rev_db = $row[0];
  if ("$server_rev_db" ne "") {
    if ("$server_rev_db" ne "$server_rev") {
      $ts = time();
      $sql = "UPDATE serverinfo SET value = '$server_rev', timestamp = '$ts' WHERE name = 'updaterev'";
      $ec = $dbh->do($sql);
    }
  }
}
