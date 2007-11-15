#!/usr/bin/perl

######################################
# Scanbinaries script                #
# SURFnet IDS                        #
# Version 2.10.02                    #
# 05-11-2007                         #
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
# 2.10.02 Added more scan methods
# 2.10.01 Added scan method support
# 2.00.02 added qw(localtime)
# 2.00.01 version 2.00
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
# Functions
##################

##################
# Main script
##################

printlog("Starting scanbinaries.pl");

# Connect to the database (dbh = DatabaseHandler or linkserver)
$checkdb = connectdb();

# Virus scanner declarations
$sql_scanners = "SELECT id, name, command, update, vercommand, version FROM scanners WHERE status = 1";
$sth_scanners = $dbh->prepare($sql_scanners);
$result_scanners = $sth_scanners->execute();

while(@temp = $sth_scanners->fetchrow_array) {
  $id = $temp[0];
  $name = $temp[1];
  $command = $temp[2];
  $update = $temp[3];
  $vercom = $temp[4];
  $version = $temp[5];

  $scanners{$id}{name} = $name;
  $scanners{$id}{command} = $command;
  $scanners{$id}{update} = $update;
  $scanners{$id}{count} = 0;
  if ($update) {
    print "Updating $name\n";
    `$update`;
  }
  if ("$vercom" ne "") {
    $ver = `$vercom`;
    chomp($ver);
    if ("$version" ne "$ver") {
      $sql_ver = "UPDATE scanners SET version = '$ver' WHERE id = '$id'";
      $sth_ver = $dbh->prepare($sql_ver);
      $result_ver = $sth_ver->execute();
    }
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

$total_files = 0;

# For each file in the nepenthes binaries directory we get some info.
if (!@ARGV) {
  opendir BINDIR, $c_bindir;
  @dircontents = grep !/^\.\.?$/, readdir BINDIR;
} else {
  @dircontents = @ARGV;
}
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
  $sql_checkbin = "SELECT bin, last_scanned FROM binaries_detail WHERE bin = $bin_id";
  $sth_checkbin = $dbh->prepare($sql_checkbin);
  $result_checkbin = $sth_checkbin->execute();
  $numrows_checkbin = $sth_checkbin->rows;
  @row_details = $sth_checkbin->fetchrow_array;
  $last_scanned = $row_detail[1];
  if ("$last_scanned" eq "") {
    $last_scanned = time();
  }

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

  $scan = 0;
  $time = time();
  if ($c_scan_method == 0) {
    $scan = 1;
  } elsif ($c_scan_method == 1) {
    # Checking if the binary is a new binary
    $sql_checkbin = "SELECT id FROM binaries WHERE bin = $bin_id";
    $sth_checkbin = $dbh->prepare($sql_checkbin);
    $result_checkbin = $sth_checkbin->execute();
    $numrows_checkbin = $sth_checkbin->rows;

    if ($numrows_checkbin == 0) {
      $scan = 1;
    }

    # Checking if the binary needs to be scanned again versus last_scanned
    $checkts = $last_scanned + $c_scan_period;
    if ($time > $checkts) {
      $scan = 1;
    }
  } elsif ($c_scan_method == 2) {
    # Checking if the binary is a new binary
    $sql_checkbin = "SELECT id FROM binaries WHERE bin = $bin_id";
    $sth_checkbin = $dbh->prepare($sql_checkbin);
    $result_checkbin = $sth_checkbin->execute();
    $numrows = $sth_checkbin->rows;
    if ($numrows == 0) {
      $scan = 1;
    }

    # Checking if the binary is not detected by certain scanners
    $sql_checkbin = "SELECT binaries.id FROM binaries, stats_virus WHERE binaries.info = stats_virus.id AND ";
    $sql_checkbin .= " stats_virus.name = 'Suspicious' AND binaries.bin = $bin_id";
    $sth_checkbin = $dbh->prepare($sql_checkbin);
    $result_checkbin = $sth_checkbin->execute();
    $numrows = $sth_checkbin->rows;
    if ($numrows != 0) {
      $scan = 1;
    }

    # Checking if the binary needs to be scanned again versus last_scanned
    $checkts = $last_scanned + $c_scan_period;
    if ($time > $checkts) {
      $scan = 1;
    }
  }

  if ($scan == 1) {
    $sql_time = "UPDATE binaries_detail SET last_scanned = '$time' WHERE bin = '$bin_id'";
    $sth_time = $dbh->prepare($sql_time);
    $result_time = $sth_time->execute();

    print "Scanning $file - ID: $bin_id\n";
    $total_files++;
    for my $key ( keys %scanners ) {
      $name = $scanners{$key}{name};
      if (!$scanners{$key}{count}) {
        $scanners{$key}{count} = 0;
      }
      $cmd = $scanners{$key}{command};
      $cmd =~ s/!bindir!/$c_bindir/g;
      $cmd =~ s/!file!/$file/g;
      $virus = `$cmd`;
      chomp($virus);
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
      print "\t$name:\t\t$virus ($virus_id)\n";

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
  } else {
    print "Skipping $file - ID: $bin_id\n";
  }
}
# Print a total overview of the scan results.
printlog("Scanned files: $total_files");
print "Scanned files: $total_files\n";

for $key ( keys %scanners ) {
  $name = $scanners{$key}{name};
  $count = $scanners{$key}{count};
  printlog("$name new: $count");
  print "$name new: $count\n";
}

printlog("-------------finished scanbinaries.pl-----------");

closedir BINDIR;
$dbh = "";
close(LOG);
