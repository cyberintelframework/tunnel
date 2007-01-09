#!/usr/bin/perl -w

######################################
# Scanbinaries script                #
# SURFnet IDS                        #
# Version 1.04.01                    #
# 07-11-2006                         #
# Jan van Lith & Kees Trippelvitz    #
######################################

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

#########################################################################
# Changelog:
# 1.04.01 Code layout
# 1.03.01 Released as part of the 1.03 package
# 1.02.05 Added sql to fill the stats_virus and stats_dialogue tables
# 1.02.04 Added more comments
# 1.02.03 Database logging instead of virusinfo files
# 1.02.02 Initial release
#########################################################################

####################
# Modules used
####################
use DBI;
use Time::localtime;

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
# Functions
##################

##################
# Main script
##################

printlog("Starting scanbinaries.pl");

# Connect to the database (dbh = DatabaseHandler or linkserver)
$checkdb = connectdb();

# Virus scanner declarations
$sql_scanners = "SELECT id, name, command, update FROM scanners WHERE status = 1";
$sth_scanners = $dbh->prepare($sql_scanners);
$result_scanners = $sth_scanners->execute();

while(@temp = $sth_scanners->fetchrow_array) {
  $id = $temp[0];
  $name = $temp[1];
  $command = $temp[2];
  $update = $temp[3];

  $scanners{$id}{name} = $name;
  $scanners{$id}{command} = $command;
  $scanners{$id}{update} = $update;
  $scanners{$id}{count} = 0;
  if ($update) {
    print "Updating $name\n";
    `$update`;
  }
}

$total_files = 0;

##################
# FILLING STATS_DIALOGUE
##################
$sql_dia = "SELECT DISTINCT text FROM details WHERE type = 1 AND text LIKE '%Dialogue'";
$sth_dia = $dbh->prepare($sql_dia);
$result_dia = $sth_dia->execute();

while(@dialogues = $sth_dia->fetchrow_array) {
  $dia = $dialogues[0];

  $sql_checkdia = "SELECT name FROM stats_dialogue WHERE name = '$dia'";
  $sth_checkdia = $dbh->prepare($sql_checkdia);
  $result_checkdia = $sth_checkdia->execute();
  $numrows_checkdia = $sth_checkdia->rows;
  if ($numrows_checkdia == 0) {
    printlog("[dialogue] Adding new dialogue: $dia");
    $sql_adddia = "INSERT INTO stats_dialogue (name) VALUES ('$dia')";
    $sth_adddia = $dbh->prepare($sql_adddia);
    $result_adddia = $sth_adddia->execute();
  }
}

# For each file in the nepenthes binaries directory we get some info.
opendir BINDIR, $c_bindir;
@dircontents = grep !/^\.\.?$/, readdir BINDIR;
foreach $file ( @dircontents ) {

  ##############
  # UNIQ_BINARIES
  ##############
  # Check if the binary was already in the uniq_binaries table.
  $sql_checkbin = "SELECT id FROM uniq_binaries WHERE name = '$file'";
  $sth_checkbin = $dbh->prepare($sql_checkbin);
  $result_checkbin = $sth_checkbin->execute();
  $numrows_checkbin = $sth_checkbin->rows;

  if ($numrows_checkbin == 0) {
    printlog("[binary] Adding new binary: $file");
    $sql_checkbin = "INSERT INTO uniq_binaries (name) VALUES ('$file')";
    $sth_checkbin = $dbh->prepare($sql_checkbin);
    $result_checkbin = $sth_checkbin->execute();

    $sql_checkbin = "SELECT id FROM uniq_binaries WHERE name = '$file'";
    $sth_checkbin = $dbh->prepare($sql_checkbin);
    $result_checkbin = $sth_checkbin->execute();
  }

  # Get the ID of the binary
  @row = $sth_checkbin->fetchrow_array;
  $bin_id = $row[0];

  ##############
  # BINARIES_DETAIL
  ##############
  # Check if the binary was already in the binaries_detail table.
  $sql_checkbin = "SELECT bin FROM binaries_detail WHERE bin = $bin_id";
  $sth_checkbin = $dbh->prepare($sql_checkbin);
  $result_checkbin = $sth_checkbin->execute();
  $numrows_checkbin = $sth_checkbin->rows;

  if ($numrows_checkbin == 0) {
    printlog("[detail] Adding new binary_detail info for binary ID: $bin_id");
    # If not, we add the filesize and file info to the database.
    # Getting the info from linux file command.
    $filepath = "$c_bindir/$file";
    $fileinfo = `file $filepath`;
    @fileinfo = split(/:/, $fileinfo);
    $fileinfo = $fileinfo[1];
    chomp($fileinfo);

    # Getting the file size.
    $filesize = (stat($filepath))[7];

    $sql_checkbin = "INSERT INTO binaries_detail (bin, fileinfo, filesize) VALUES ($bin_id, '$fileinfo', $filesize)";
    $sth_checkbin = $dbh->prepare($sql_checkbin);
    $result_checkbin = $sth_checkbin->execute();
  }

  print "Scanning $file - ID: $bin_id\n";
  $total_files++;
  $time = time();
  for my $key ( keys %scanners ) {
    $name = $scanners{$key}{name};
    $cmd = $scanners{$key}{command};
    $cmd =~ s/!bindir!/$c_bindir/g;
    $cmd =~ s/!file!/$file/g;
    $virus = `$cmd`;
    chomp($virus);
    print "\t$name:\t\t$virus\n";
    if ($virus eq "") {
      $virus = "Suspicious";
    }

    $sql_virus = "SELECT id FROM stats_virus WHERE name = '$virus'";
    $sth_virus = $dbh->prepare($sql_virus);
    $result_virus = $sth_virus->execute();
    if ($result_virus == 0) {
      printlog("[virus] Adding new virus: $virus");
      # The virus was not yet in the stats_virus table. Insert it.
      $sql_insert = "INSERT INTO stats_virus (name) VALUES ('$virus')";
      $sth_insert = $dbh->prepare($sql_insert);
      $result_insert = $sth_insert->execute();

      $sql_virus = "SELECT id FROM stats_virus WHERE name = '$virus'";
      $sth_virus = $dbh->prepare($sql_virus);
      $result_virus = $sth_virus->execute();
    }
    @temp = $sth_virus->fetchrow_array;
    $virus_id = $temp[0];

    # We check if this binary and the scan result were already in the database. The unique key here is $file, $scanner, $virus.
    $sql_select = "SELECT * FROM binaries WHERE bin = $bin_id AND info = $virus_id AND scanner = $key";
    $sth_select = $dbh->prepare($sql_select);
    $result_select = $sth_select->execute();
    $numrows_select = $sth_select->rows;
    if ($numrows_select == 0) {
      # The combination of $file, $scanner and $virus was not yet in the database. Insert it.
      $scanners{$key}{count}++;
      $sql_insert = "INSERT INTO binaries (timestamp, bin, info, scanner) VALUES ($time, $bin_id, $virus_id, $key)";
      $sth_insert = $dbh->prepare($sql_insert);
      $result_insert = $sth_insert->execute();
    }
  }
}
# Print a total overview of the scan results.
printlog("Scanned files: $total_files");
print "[$ts] Scanned files: $total_files\n";

for $key ( keys %scanners ) {
  $name = $scanners{$key}{name};
  $count = $scanners{$key}{count};
  printlog("$name new: $count");
  print "[$ts] $name new: $count\n";
}

printlog("-------------finished scanbinaries.pl-----------");

closedir BINDIR;
$dbh = "";
close(LOG);
