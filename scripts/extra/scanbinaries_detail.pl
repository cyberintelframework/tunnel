#!/usr/bin/perl

##################
# Modules used
##################
use DBI;
use Time::localtime;

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

sub getec {
  if ($? == 0) {
    my $ec = "Ok";
  }
  else {
    my $ec = "Err - $?";
  }
}

##################
# Main script
##################


# Connect to the database (dbh = DatabaseHandler or linkserver)
$dbh = DBI->connect($dsn, $pgsql_user, $pgsql_pass)
        or die $DBI::errstr;

$bindir = "/home/nepenthes/var/binaries/";

$added = 0;
$total = 0;

opendir BINDIR, $bindir;
@dircontents = grep !/^\.\.?$/, readdir BINDIR;
foreach $file ( @dircontents ) {

  $sql_checkbin = "SELECT bin FROM binaries_detail WHERE bin = '$file'";
  $sth_checkbin = $dbh->prepare($sql_checkbin);
  $result_checkbin = $sth_checkbin->execute();
  $numrows_checkbin = $sth_checkbin->rows;

  if ($numrows_checkbin == 0) {
    $filepath = "$bindir/$file";
    $fileinfo = `file $filepath`;
    @fileinfo = split(/:/, $fileinfo);
    $fileinfo = $fileinfo[1];
    chomp($fileinfo);

    $filesize = (stat($filepath))[7];

    $sql_checkbin = "INSERT INTO binaries_detail (bin, fileinfo, filesize) VALUES ('$file', '$fileinfo', $filesize)";
    $sth_checkbin = $dbh->prepare($sql_checkbin);
    $result_checkbin = $sth_checkbin->execute();
    $added++;
  }
  $total++;
}

print "Added $added new files\n";
print "Total $total files\n";
