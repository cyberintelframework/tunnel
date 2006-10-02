#!/usr/bin/perl
print "--- start ---\n";
use DBI;
do '/etc/surfnetids/surfnetids-tn.conf';

# Connect to the database (dbh = DatabaseHandler or linkserver)
$dbh = DBI->connect($dsn, $pgsql_user, $pgsql_pass)
or die $DBI::errstr;

$sth = $dbh->prepare("
  SELECT mac.mac
  FROM   sensors, mac
  WHERE  sensors.keyname = '$sensor'
    AND  sensors.id = mac.sensor_id
    AND  mac.id NOT IN
        (SELECT tap.mac_id
         FROM   tap, sensors
         WHERE sensors.keyname = 'sensor13'
           AND sensors.id = tap.sensor_id )

");
print "error: ";
print $DBI::errstr;
print "\n";
$execute_result = $sth->execute();
@row = $sth->fetchrow_array;
$mac = $row[0];
print "Mac: $mac\n";
print "--- stop ---\n";

