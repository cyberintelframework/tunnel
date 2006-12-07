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
} else {
  $logfile = "$surfidsdir/log/$logfile";
}

##################
# Virus scanner declarations
##################

%scanners = (
	1 => {
		name = "ClamAV",
		command = "clamscan --no-summary !bindir!/!file! | grep !file! | awk '{print \$2}'",
		update = "freshclam",
	},
	2 => {
		name = "Antivir",
		command = "antivir -rs !bindir!/!file! | grep !file! | awk '{print \$2}' | awk -F [ '{print \$1}'",
		update = "antivir --update",
	},
	3 => {
		name = "BitDefender",
		command = "bdc --files !bindir!/!file! | grep !file! | awk '{print \$3}'",
		update = "bdc --update",
	}
)


##################
# Functions
##################

sub getts {
  my $ts = time();
  my $year = localtime->year() + 1900;
  my $month = localtime->mon() + 1;
  if ($month < 10) {
    $month = "0" . $month;
  }
  my $day = localtime->mday();
  if ($day < 10) {
    $day = "0" . $day;
  }
  my $hour = localtime->hour();
  if ($hour < 10) {
    $hour = "0" . $hour;
  }
  my $min = localtime->min();
  if ($min < 10) {
    $min = "0" . $min;
  }
  my $sec = localtime->sec();
  if ($sec < 10) {
    $sec = "0" . $sec;
  }

  my $timestamp = "$day-$month-$year $hour:$min:$sec";
}

##################
# Main script
##################

# Opening log file
open(LOG, ">> $logfile");

$ts = getts();
print LOG "[$ts] Starting binaries.pl\n";

# Connect to the database (dbh = DatabaseHandler or linkserver)
$dbh = DBI->connect($dsn, $pgsql_user, $pgsql_pass)
        or die $DBI::errstr;

$total_files = 0;
$clamav_new = 0;
$antivir_new = 0;
$bdc_new = 0;

#$bindir = "/opt/surfnetids/webinterface/virusinfo";

# Before we start scanning, we update the virusscanners.
`freshclam`;
print "Updating ClamAV\n";
if ($bdc == 1) {
  `bdc --update`;
  print "Updating BitDefender\n"; 
}
if ($antivir == 1) {
  `antivir --update`;
   print "Updating Antivir\n";
}

# While block to fill the stats_dialogue table
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
    $sql_adddia = "INSERT INTO stats_dialogue (name) VALUES ('$dia')";
    $sth_adddia = $dbh->prepare($sql_adddia);
    $result_adddia = $sth_adddia->execute();
  }
}

# For each file in the nepenthes binaries directory we get some info.
opendir BINDIR, $bindir;
@dircontents = grep !/^\.\.?$/, readdir BINDIR;
foreach $file ( @dircontents ) {

  # Check if the binary was already in the binaries_detail table.
  $sql_checkbin = "SELECT bin FROM binaries_detail WHERE bin = '$file'";
  $sth_checkbin = $dbh->prepare($sql_checkbin);
  $result_checkbin = $sth_checkbin->execute();
  $numrows_checkbin = $sth_checkbin->rows;

  if ($numrows_checkbin == 0) {
    # If not, we add the filesize and file info to the database.
    # Getting the info from linux file command.
    $filepath = "$bindir/$file";
    $fileinfo = `file $filepath`;
    @fileinfo = split(/:/, $fileinfo);
    $fileinfo = $fileinfo[1];
    chomp($fileinfo);

    # Getting the file size.
    $filesize = (stat($filepath))[7];

    $sql_checkbin = "INSERT INTO binaries_detail (bin, fileinfo, filesize) VALUES ('$file', '$fileinfo', $filesize)";
    $sth_checkbin = $dbh->prepare($sql_checkbin);
    $result_checkbin = $sth_checkbin->execute();
  }

  print "Scanning $file\n";
  $total_files++;
  $time = time();

  ###### ClamAV ######
  $virinfo = `clamscan --no-summary $bindir/$file`;
  @virinfo_ar = split(/ +/, $virinfo);
  $virus = $virinfo_ar[1];
  chomp($virus);

  # Even if ClamAV indicates that the binary was clean (OK) it is still a suspicious file.
  if ($virus eq "OK") {
    $virus = "Suspicious";
  }

  print "\tClamAV: $virus\n";

  $sql_virus = "SELECT id FROM stats_virus WHERE name = '$virus'";
  $sth_virus = $dbh->prepare($sql_virus);
  $result_virus = $sth_virus->execute();
  if ($result_virus == 0) {
    # The virus was not yet in the stats_virus table. Insert it.
    $sql_insert = "INSERT INTO stats_virus (name) VALUES ('$virus')";
    $sth_insert = $dbh->prepare($sql_insert);
    $result_insert = $sth_insert->execute();
  }

  # We check if this binary and the scan result were already in the database. The unique key here is $file, $scanner, $virus.
  $sql_select = "SELECT * FROM binaries WHERE bin = '$file' AND info = '$virus' AND scanner = 'ClamAV'";
  $sth_select = $dbh->prepare($sql_select);
  $result_select = $sth_select->execute();
  if ($result_select == 0) {
    # The combination of $file, $scanner and $virus was not yet in the database. Insert it.
    $clamav_new++;
    $sql_insert = "INSERT INTO binaries (timestamp, bin, info, scanner) VALUES ($time, '$file', '$virus', 'ClamAV')";
    $sth_insert = $dbh->prepare($sql_insert);
    $result_insert = $sth_insert->execute();
  }

  ###### Bitdefender ######
  if ($bdc == 1) {
    $virinfo=`bdc --files $bindir/$file | grep "/.*[infected|suspected].*/"`;
    @virinfo_ar = split(/ +/, $virinfo);
    $virinfo = $virinfo_ar[2];
    if ($virinfo =~ /.*:.*/) {
      @virinfo_ar = split(/:/, $virinfo);
      $virus = "$virinfo_ar[1]";
    } else {
      $virus = $virinfo;
    }
    chomp($virus);

    if ($virus eq "") {
      $virus = "Suspicious";
    }

    $sql_virus = "SELECT id FROM stats_virus WHERE name = '$virus'";
    $sth_virus = $dbh->prepare($sql_virus);
    $result_virus = $sth_virus->execute();
    if ($result_virus == 0) {
      # The virus was not yet in the stats_virus table. Insert it.
      $sql_insert = "INSERT INTO stats_virus (name) VALUES ('$virus')";
      $sth_insert = $dbh->prepare($sql_insert);
      $result_insert = $sth_insert->execute();
    }

    print "\tBitDefender: $virus\n";

    $sql_select = "SELECT * FROM binaries WHERE bin = '$file' AND info = '$virus' AND scanner = 'BitDefender'";
    $sth_select = $dbh->prepare($sql_select);
    $result_select = $sth_select->execute();
    if ($result_select == 0) {
      $bdc_new++;
      $sql_insert = "INSERT INTO binaries (timestamp, bin, info, scanner) VALUES ($time, '$file', '$virus', 'BitDefender')";
      $sth_insert = $dbh->prepare($sql_insert);
      $result_insert = $sth_insert->execute();
    }
  }

  ###### Avira Antivir ######
  if ($antivir == 1) {
    $virinfo=`antivir -rs $bindir/$file | grep "ALERT:"`;
    chomp($virinfo);
    @vir_ar = split(/\[/, $virinfo);
    $virinfo = $vir_ar[1];
    @vir_ar = split(/\]/, $virinfo);
    $virinfo = "$vir_ar[0]";
    @vir_ar = split(/ +/, $virinfo);
    $virus = $vir_ar[0];
    chomp($virus);

    if ($virus eq "") {
      $virus = "Suspicious";
    }

    $sql_virus = "SELECT id FROM stats_virus WHERE name = '$virus'";
    $sth_virus = $dbh->prepare($sql_virus);
    $result_virus = $sth_virus->execute();
    if ($result_virus == 0) {
      # The virus was not yet in the stats_virus table. Insert it.
      $sql_insert = "INSERT INTO stats_virus (name) VALUES ('$virus')";
      $sth_insert = $dbh->prepare($sql_insert);
      $result_insert = $sth_insert->execute();
    }

    print "\tAntivir: $virus\n";

    $sql_select = "SELECT * FROM binaries WHERE bin = '$file' AND info = '$virus' AND scanner = 'Antivir'";
    $sth_select = $dbh->prepare($sql_select);
    $result_select = $sth_select->execute();
    if ($result_select == 0) {
      $antivir_new++;
      $sql_insert = "INSERT INTO binaries (timestamp, bin, info, scanner) VALUES ($time, '$file', '$virus', 'Antivir')";
      $sth_insert = $dbh->prepare($sql_insert);
      $result_insert = $sth_insert->execute();
    }
  }
}
# Print a total overview of the scan results.
$ts = getts();
print LOG "[$ts] Scanned files: $total_files\n";
print "[$ts] Scanned files: $total_files\n";

print LOG "[$ts] ClamAV new: $clamav_new\n";
print "[$ts] ClamAV new: $clamav_new\n";

if ($bdc == 1) {
  print LOG "[$ts] BitDefender new: $bdc_new\n";
  print "[$ts] BitDefender new: $bdc_new\n";
}

if ($antivir == 1) {
  print LOG "[$ts] Antivir new: $antivir_new\n";
  print "[$ts] Antivir new: $antivir_new\n";
}

print LOG "-------------finished binaries.pl-----------\n";

closedir BINDIR;
$dbh = "";
close(LOG);
