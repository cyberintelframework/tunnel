#!/usr/bin/perl

########################################
# IDMEF script for IDS server database #
# SURFnet IDS          	               #
# Version 1.02.02        	       #
# 12-04-2006          	               #
# Jan van Lith & Kees Trippelvitz      #
########################################

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

##################
# Modules used
##################
use DBI;
use Time::localtime;
use Time::Local;

##################
# Variables used
##################
do '/etc/surfnetids/surfnetids-log.conf';
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
  $logfile = "$surfidsdir/log/$day$month$year/$logfile";
}
else {
  $logfile = "$surfidsdir/log/$logfile";
}

##################
# Functions
##################

sub getts {
  my $ts = time();
  my $tsyear = localtime->year() + 1900;
  my $tsmonth = localtime->mon() + 1;
  if ($tsmonth < 10) {
    $tsmonth = "0" . $tsmonth;
  }
  my $tsday = localtime->mday();
  if ($tsday < 10) {
    $tsday = "0" . $tsday;
  }
  my $tshour = localtime->hour();
  if ($tshour < 10) {
    $tshour = "0" . $tshour;
  }
  my $tsmin = localtime->min();
  if ($tsmin < 10) {
    $tsmin = "0" . $tsmin;
  }
  my $tssec = localtime->sec();
  if ($tssec < 10) {
    $tssec = "0" . $tssec;
  }

  my $timestamp = "$tsday-$tsmonth-$tsyear $tshour:$tsmin:$tssec";
}

##################
# Main script
##################

# Opening log file
open(LOG, ">> $logfile");
$ts = getts();
print LOG "[$ts] Starting idmef.pl\n";

# Connect to the database (dbh = DatabaseHandler or linkserver)
$dbh = DBI->connect($dsn, $pgsql_user, $pgsql_pass)
        or die $DBI::errstr;
$ts = getts();
print LOG "[$ts] Connecting to $pgsql_dbname with DSN: $dsn\n";
print LOG "[$ts] Connect result: $dbh\n";

# For all organisations but ADMIN create an idmef file.
$sensor_query = $dbh->prepare("SELECT id, organisation FROM organisations WHERE NOT organisation = 'ADMIN'");
$execute_result = $sensor_query->execute();
print LOG "[$ts] Total sensors: $execute_result\n";
while (@orgs = $sensor_query->fetchrow_array) {
  $org_id = $orgs[0];
  $org = $orgs[1];
  $now = time();
  $last = $now - 86400;

  # Setting up access to the idmef directory, if it doesn't exist yet.
  if (-e "$xmldir/.htaccess") {
    $searchhtaccess = `cat $xmldir/.htaccess | grep "$org" | wc -l`;
  }
  else {
    `touch $xmldir/.htaccess`;
    $searchhtaccess = 0;
  }
  if ( $searchhtaccess == 0 ) {
    open(HTA, ">> $xmldir/.htaccess");
    print HTA "\n";
    print HTA "<FilesMatch $org.xml>\n";
    print HTA "AuthType basic\n";
    print HTA "AuthName \"$org IDMEF Log\"\n";
    print HTA "Auth_PG_database idsserver\n";
    print HTA "Auth_PG_user $pgsql_user\n";
    print HTA "Auth_PG_pwd $pgsql_pass\n";
    print HTA "Auth_PG_hash_type MD5\n";
    print HTA "Auth_PG_pwd_table login\n";
    print HTA "Auth_PG_uid_field username\n";
    print HTA "Auth_PG_pwd_field password\n";
    print HTA "Auth_PG_pwd_whereclause \" and organisation = $org_id \"\n";
    print HTA "Require valid-user\n";
    print HTA "</FilesMatch>\n";
    close(HTA);

    open(HTP, "> $xmldir/.htpasswd_$org");
    $login_query = $dbh->prepare("SELECT username, password FROM login WHERE organisation = $org_id");
    $execute_result = $login_query->execute();
    while (@login = $login_query->fetchrow_array) {
      $username = $login[0];
      $pass = $login[1];
      $htpass_string = "$username:$pass";
      open(HTP, ">> $xmldir/.htpasswd_$org");
      print HTP "$htpass_string\n";
    }
    close(HTP);
  }

  ### Creating the xml file.
  $idmeffile = $org . ".xml";
  open(IDMEF, "> $xmldir/$idmeffile");
  print IDMEF "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
  print IDMEF "<!DOCTYPE IDMEF-Message PUBLIC \"-//IETF//DTD RFC XXXX IDMEF v1.0//EN\" \"idmef-message.dtd\">\n";
  print IDMEF "<idmef:IDMEF-Message version=\"1.0\" xmlns:idmef=\"http://iana.org/idmef\">\n";
#  print "SELECT attacks.*, sensors.keyname, details.text FROM attacks, sensors, details WHERE attacks.sensorid = sensors.id AND attacks.severity = 1\n";
#  print "AND attacks.timestamp >= '$last' AND attacks.timestamp <= '$now' AND details.attackid = attacks.id AND details.text LIKE '%Dialogue'\n";
#  print "AND sensors.organisation = $org_id\n";
  $attack_query = $dbh->prepare("SELECT attacks.*, sensors.keyname, details.text FROM attacks, sensors, details WHERE attacks.sensorid = sensors.id AND 
                                 attacks.severity = 1 AND attacks.timestamp >= '$last' AND attacks.timestamp <= '$now' AND 
                                 details.attackid = attacks.id AND details.text LIKE '%Dialogue' AND sensors.organisation = $org_id");
  $attack_result = $attack_query->execute();
  print LOG "[$ts] Amount of alerts for $org: $attack_result\n";
  while (@row = $attack_query->fetchrow_array) {
    $id = $row[0];
    $timestamp = $row[1];
    $source = $row[3];
    $sport = $row[4];
    $dest = $row[5];
    $dport = $row[6];
    $keyname = $row[8];
    $attack = $row[9];
    @attack_ar = split(/Dialogue/, $attack);
    $attack = $attack_ar[0];
    print IDMEF "\t<idmef:Alert messageid=\"$id\">\n";
      print IDMEF "\t\t<idmef:Analyzer analyzerid=\"$keyname\">\n";
      print IDMEF "\t\t</idmef:Analyzer>\n";
      print IDMEF "\t\t<idmef:CreateTime>$timestamp</idmef:CreateTime>\n";
      print IDMEF "\t\t<idmef:Source>\n";
        print IDMEF "\t\t\t<idmef:Node>\n";
          print IDMEF "\t\t\t\t<idmef:Address category=\"ipv4-addr\">\n";
            print IDMEF "\t\t\t\t\t<idmef:address>$source</idmef:address>\n";
          print IDMEF "\t\t\t\t</idmef:Address>\n";
        print IDMEF "\t\t\t</idmef:Node>\n";
        print IDMEF "\t\t\t<idmef:Service>\n";
          print IDMEF "\t\t\t\t<idmef:port>$sport</idmef:port>\n";
        print IDMEF "\t\t\t</idmef:Service>\n";
      print IDMEF "\t\t</idmef:Source>\n";
      print IDMEF "\t\t<idmef:Target>\n";
        print IDMEF "\t\t\t<idmef:Node>\n";
          print IDMEF "\t\t\t\t<idmef:Address category=\"ipv4-addr\">\n";
            print IDMEF "\t\t\t\t\t<idmef:address>$dest</idmef:address>\n";
          print IDMEF "\t\t\t\t</idmef:Address>\n";
        print IDMEF "\t\t\t</idmef:Node>\n";
        print IDMEF "\t\t\t<idmef:Service>\n";
          print IDMEF "\t\t\t\t<idmef:port>$dport</idmef:port>\n";
        print IDMEF "\t\t\t</idmef:Service>\n";
      print IDMEF "\t\t</idmef:Target>\n";
      print IDMEF "\t\t<idmef:AdditionalData type=\"string\" meaning=\"attack-type\">\n";
        print IDMEF "\t\t\t<idmef:string>$attack</idmef:string>\n";
      print IDMEF "\t\t</idmef:AdditionalData>\n";
    print IDMEF "\t</idmef:Alert>\n";

  }
  print IDMEF "</idmef:IDMEF-Message>\n";
  close(IDMEF);
}

$ts = getts();
print LOG "[$ts] -------------Finished idmef.pl-------------\n";
close(LOG);

# Closing database connection.
$dbh = "";
