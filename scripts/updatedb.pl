#!/usr/bin/perl

#########################################
# Update Database script for IDS server #
# SURFnet IDS                           #
# Version 1.02.03                       #
# 15-05-2006                            #
# Jan van Lith & Kees Trippelvitz       #
#########################################

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

####################
# Modules used
####################
use DBI;
use Time::localtime;

####################
# Variables used
####################
$pgsql_pass = "";
$pgsql_user = "";
$pgsql_host = "localhost";
$pgsql_dbname = "idsserver";
$pgsql_port = "5432";
$dsn = "DBI:Pg:dbname=$pgsql_dbname;host=$pgsql_host;port=$pgsql_port";

##################
# Functions
##################
sub prompt {
  local($promptstring,$defaultvalue) = @_;
  if ($defaultvalue) {
    print $promptstring, "[", $defaultvalue, "]: ";
  } else {
    print $promptstring, ": ";
  }

  $| = 1;               # force a flush after our print
  $_ = <STDIN>;         # get the input from STDIN (presumably the keyboard)

  chomp;

  if ("$defaultvalue") {
    if ($_ eq "") {
      return $defaultvalue;
    }
    else {
      return $_;
    }
  }
  else {
    return $_;
  }
}

####################
# Main script
####################
$id = 0;

if ($pgsql_user == "" || $pgsql_pass == "") {
  print "This scripts needs to be configured before it can run!\n";
  exit 1
}

### Setting server variable.
while ($server eq "") {
  $server = &prompt("Enter the IP address or domainname of the tunnel server");
}

$dbh = DBI->connect($dsn, $pgsql_user, $pgsql_pass)
        or die $DBI::errstr;

###################################################################
# STEP 0: Insert server into servers table and drop history table.
###################################################################

$sql_server = "INSERT INTO servers (server) VALUES ($server)";
$sth_server = $dbh->prepare($sql_server);
$result_server = $sth_server->execute();

$sql_getserv = "SELECT id FROM servers WHERE server = '$server'";
$sth_getserv = $dbh->prepare($sql_getserv);
$result_getserv = $sth_getserv->execute();
@row_getserv = $sth_getserv->fetchrow_array;
$servid = $row_getserv[0];

$sql_hist = "DROP TABLE history";
$sth_hist = $dbh->prepare($sql_hist);
$result_hist = $sth_hist->execute();

###########################################################
# STEP 1: Get old data from sensors table. 
###########################################################

print "Updating table: sensors\n";
$sql_old = "SELECT * FROM sensors ORDER BY id";
$sth_old = $dbh->prepare($sql_old);
$result_old = $sth_old->execute();
$i = 0;

while(@sensors = $sth_old->fetchrow_array) {
  $id = @sensors[0];
  $keyname = @sensors[1];
  $remoteip = @sensors[2];
  $localip = @sensors[3];
  $tap = @sensors[4];
  $tapip = @sensors[5];
  $lastupdate = @sensors[6];
  $laststart = @sensors[7];
  $organisation = @sensors[8];
  $reboot = @sensors[9];
  $mac = @sensors[10];

  $sql_getorg = "SELECT id FROM organisations WHERE organisation = '$organisation'";
  $sth_getorg = $dbh->prepare($sql_getorg);
  $result_getorg = $sth_getorg->execute();
  @row_getorg = $sth_getorg->fetchrow_array;
  $orgid = $row_getorg[0];

  push @data, [ $id, $keyname, $remoteip, $localip, $orgid, $mac ];
}
$maxid = $id;

###########################################################
# STEP 2a: DROP old sensors table constraints. 
###########################################################

$sql_remfd = "ALTER TABLE ONLY details DROP CONSTRAINT foreign_sensor";
$sth_remfd = $dbh->prepare($sql_remfd);
$result_remfd = $sth_remfd->execute();

$sql_remfa = "ALTER TABLE ONLY attacks DROP CONSTRAINT foreign_sensor";
$sth_remfa = $dbh->prepare($sql_remfa);
$result_remfa = $sth_remfa->execute();

$sql_remfh = "ALTER TABLE ONLY history DROP CONSTRAINT foreign_sensor";
$sth_remfh = $dbh->prepare($sql_remfh);
$result_remfh = $sth_remfh->execute();

###########################################################
# STEP 2b: DROP old sensors id sequence.
###########################################################

$sql_droptable = "DROP TABLE sensors";
$sth_droptable = $dbh->prepare($sql_droptable);
$result_droptable = $sth_droptable->execute();

###########################################################
# STEP 3: Add sensors table with the correct structure. 
###########################################################

$sql_create_sensors = <<SQL
CREATE TABLE sensors (
    id serial NOT NULL,
    keyname character varying NOT NULL,
    remoteip inet NOT NULL,
    localip inet NOT NULL,
    lastupdate integer,
    laststart integer,
    "action" character varying,
    ssh integer DEFAULT 1,
    status integer,
    uptime integer,
    laststop integer,
    tap character varying,
    tapip inet,
    mac macaddr,
    netconf text,
    server integer,
    organisation integer DEFAULT 0 NOT NULL
)
SQL
;

$sth = $dbh->prepare($sql_create_sensors);
$execute_result = $sth->execute();

###########################################################
# STEP 4: Populate the new sensors table with the old data. 
###########################################################

$i = 0;
foreach (@data) {
  $id = $data[$i][0];
  $keyname = $data[$i][1];
  $remoteip = $data[$i][2];
  $localip = $data[$i][3];
  $orgid = $data[$i][4];
  $mac = $data[$i][5];
  $i++;

  if ($mac eq "") {
    $sql_insert = "INSERT INTO sensors (id, keyname, remoteip, localip, lastupdate, laststart, action, uptime, organisation, status, server) VALUES ($id, '$keyname', '$remoteip', '$localip', 0, 0, 'CLIENT', 0, $orgid, 1, $servid)";
  }
  else {
    $sql_insert = "INSERT INTO sensors (id, keyname, remoteip, localip, lastupdate, laststart, mac, action, uptime, organisation, status, server) VALUES ($id, '$keyname', '$remoteip', '$localip', 0, 0, '$mac', 'NONE', 0, $orgid, 1, $servid)";
  }
  $sth_insert = $dbh->prepare($sql_insert);
  $result_insert = $sth_insert->execute();
}

###########################################################
# STEP 5: SET the sensors_id_seq to the correct value. 
###########################################################

$sql_resetseq = "ALTER SEQUENCE sensors_id_seq RESTART WITH $maxid";
$sth_resetseq = $dbh->prepare($sql_resetseq);
$result_resetseq = $sth_resetseq->execute();

###########################################################
# STEP 6: ADD new sensors table constraints. 
###########################################################

$sql_addps = "ALTER TABLE ONLY sensors ADD CONSTRAINT primary_sensors PRIMARY KEY (id)";
$sth_addps = $dbh->prepare($sql_addps);
$result_addps = $sth_addps->execute();

$sql_addfd = "ALTER TABLE ONLY details ADD CONSTRAINT foreign_sensor FOREIGN KEY (sensorid) REFERENCES sensors(id)";
$sth_addfd = $dbh->prepare($sql_addfd);
$result_addfd = $sth_addfd->execute();

$sql_addfa = "ALTER TABLE ONLY attacks ADD CONSTRAINT foreign_sensor FOREIGN KEY (sensorid) REFERENCES sensors(id)";
$sth_addfa = $dbh->prepare($sql_addfa);
$result_addfa = $sth_addfa->execute();

$sql_addfh = "ALTER TABLE ONLY history ADD CONSTRAINT foreign_sensor FOREIGN KEY (sensorid) REFERENCES sensors(id)";
$sth_addfh = $dbh->prepare($sql_addfh);
$result_addfh = $sth_addfh->execute();

###########################################################
# STEP 7: SET the correct privileges for the sensors table.
###########################################################

$sql_grantsens = "GRANT INSERT,SELECT,UPDATE ON TABLE sensors TO idslog";
$sth_grantsens = $dbh->prepare($sql_grantsens);
$result_grantsens = $sth_grantsens->execute();

$sql_grantsens = "GRANT SELECT ON TABLE sensors TO nepenthes";
$sth_grantsens = $dbh->prepare($sql_grantsens);
$result_grantsens = $sth_grantsens->execute();

$sql_grantsens = "GRANT ALL ON TABLE sensors_id_seq TO idslog;";
$sth_grantsens = $dbh->prepare($sql_grantsens);
$result_grantsens = $sth_grantsens->execute();

###########################################################
# STEP 8: GET the old login table data. 
###########################################################

print "Updating table: login\n";
$sql_oldlogin = "SELECT * FROM login ORDER BY id";
$sth_oldlogin = $dbh->prepare($sql_oldlogin);
$result_oldlogin = $sth_oldlogin->execute();
$i = 0;

while(@login = $sth_oldlogin->fetchrow_array) {
  $id = @login[0];
  $username = @login[1];
  $password = @login[2];
  $organisation = @login[3];
  $email = @login[4];
  if ($organisation == "ADMIN") {
    $access = "999";
  }
  else {
    $access = "011";
  }

  $sql_getorg = "SELECT id FROM organisations WHERE organisation = '$organisation'";
  $sth_getorg = $dbh->prepare($sql_getorg);
  $result_getorg = $sth_getorg->execute();
  @row_getorg = $sth_getorg->fetchrow_array;
  $orgid = $row_getorg[0];

  push @data_login, [ $id, $username, $password, $email, $orgid, $access ];
}
$maxid_login = $id;

###########################################################
# STEP 9: DROP login table
###########################################################

$sql_droplogin = "DROP TABLE login";
$sth_droplogin = $dbh->prepare($sql_droplogin);
$result_droplogin = $sth_droplogin->execute();

###########################################################
# STEP 10: CREATE NEW login table
###########################################################

$sql_create_login = <<SQL
CREATE TABLE login (
    id serial NOT NULL,
    username character varying NOT NULL,
    "password" character varying NOT NULL,
    email character varying,
    maillog integer DEFAULT 0,
    lastlogin integer,
    organisation integer DEFAULT 0 NOT NULL,
    "access" character varying DEFAULT '000'::character varying NOT NULL
)
SQL
;

$sth = $dbh->prepare($sql_create_login);
$execute_result = $sth->execute();

###########################################################
# STEP 11: Populate the new login table with the old data. 
###########################################################

$i = 0;
foreach (@data_login) {
  $log_id = $data_login[$i][0];
  $log_username = $data_login[$i][1];
  $log_password = $data_login[$i][2];
  $log_email = $data_login[$i][3];
  $log_organisation = $data_login[$i][4];
  $log_access = $data_login[$i][5];
  $i++;

  if ($log_organisation == "") {
    print "Account $log_username didn't have a correct organisation.\n";
    print "Organisation set to 0. This needs to be fixed after the update\n\n";
    $log_organisation = 0;
  }
  $sql_insert_login = "INSERT INTO login (id, username, password, email, maillog, lastlogin, organisation, access) VALUES ($log_id, '$log_username', '$log_password', '$log_email', 0, 0, $log_organisation, '$log_access')";
  $sth_insert_login = $dbh->prepare($sql_insert_login);
  $result_insert_login = $sth_insert_login->execute();
}

###########################################################
# STEP 12: SET the login_id_seq to the correct value. 
###########################################################

$sql_resetlogseq = "ALTER SEQUENCE login_id_seq RESTART WITH $maxid_login";
$sth_resetlogseq = $dbh->prepare($sql_resetlogseq);
$result_resetlogseq = $sth_resetlogseq->execute();

###########################################################
# STEP 13: SET the correct privileges for the login table. 
###########################################################

$sql_grantlogin = "GRANT INSERT,SELECT,UPDATE,DELETE ON TABLE login TO idslog";
$sth_grantlogin = $dbh->prepare($sql_grantlogin);
$result_grantlogin = $sth_grantlogin->execute();

$sql_grantlogin = "GRANT ALL ON TABLE login_id_seq TO idslog;";
$sth_grantlogin = $dbh->prepare($sql_grantlogin);
$result_grantlogin = $sth_grantlogin->execute();

print "Finished...\n";
print "Check the permissions for the login and sensors table and the login_id_seq and sensors_id_seq\n";
print "The users for nepenthes and the webinterface (default: idslog) should have the correct permissions.\n";
