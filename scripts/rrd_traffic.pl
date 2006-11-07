#!/usr/bin/perl
#####################################
# rrd_traffic script for IDS server #
# SURFnet IDS                       #
# Version 1.02.02                   #
# 26-09-2006                        #
# Jan van Lith & Kees Trippelvitz   #
#####################################

#####################
# Changelog:
# 1.02.02 Images are now stored in the database (table rrd)
# 1.02.01 Initial release
#####################

##################
# Modules used
##################
use RRDs;
use DBI;
use MIME::Base64;
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
}
else {
  $logfile = "$surfidsdir/log/$logfile";
}

##################
# Main script
##################

$dbh = DBI->connect($dsn, $pgsql_user, $pgsql_pass)
	or die $DBI::errstr;

@test = `cat /proc/net/dev | awk -F ":" '{print \$1}' | grep tap | awk '{print \$1}'`;
foreach (@test) {
  $tap = $_;
  chomp($tap);

  $sql = "SELECT sensors.keyname, organisations.organisation ";
  $sql .= "FROM sensors, organisations, org_id ";
  $sql .= "WHERE sensors.tap = '$tap' AND organisations.id = sensors.organisation";
  $sth = $dbh->prepare($sql);
  $exe = $sth->execute();
  @data = $sth->fetchrow_array;
  $keyname = $data[0];
  $org = $data[1];
  print "Processing interface $tap: $keyname - $org\n";
  &ProcessInterface("$tap", "$keyname", "$org");
}

&ProcessInterfaceALL("$totalin", "$totalout", "alltaps", "allsensors", "ADMIN");

sub ProcessInterfaceALL {
  # process interface
  # inputs: $_[0]: totalin
  #         $_[1]: totalout 
  #         $_[2]: interface name 
  #         $_[3]: interface Description 
  #         $_[4]: Organisation

  $totalin = $_[0];
  $totalout = $_[1];

  # remove eol chars
  chomp($totalin);
  chomp($totalout);

#  print "$_[3] traffic in, out: $totalin, $totalout\n";

  # if rrdtool database doesn't exist, create it
  if (! -e "$rrddir/$_[3].rrd") {
    print "creating rrd database for $_[3] ...\n";
    RRDs::create "$rrddir/$_[3].rrd",
        "-s 300",
        "DS:in:DERIVE:600:0:12500000",
        "DS:out:DERIVE:600:0:12500000",
        "RRA:AVERAGE:0.5:1:576",
        "RRA:AVERAGE:0.5:6:672",
        "RRA:AVERAGE:0.5:24:732",
        "RRA:AVERAGE:0.5:144:1460";
  }

  # insert values into rrd
  RRDs::update "$rrddir/$_[3].rrd",
        "-t", "in:out",
        "N:$totalin:$totalout";

  # create traffic graphs
  &CreateGraph($_[2], "day", $_[3], $_[4]);
  &CreateGraph($_[2], "week", $_[3], $_[4]);
  &CreateGraph($_[2], "month", $_[3], $_[4]);
  &CreateGraph($_[2], "year", $_[3], $_[4]);
}

sub ProcessInterface {
  # process interface
  # inputs: $_[0]: interface name 
  #	  $_[1]: interface description 
  #	  $_[2]: Organisation

  # get network interface info
  my $in = `ifconfig $_[0] | grep bytes | cut -d":" -f2 | cut -d" " -f1`;
  my $out = `ifconfig $_[0] | grep bytes | cut -d":" -f3 | cut -d" " -f1`;

  $totalin = $totalin += $in;
  $totalout = $totalout += $out;

  # remove eol chars
  chomp($in);
  chomp($out);

  print "$_[0] traffic in, out: $in, $out\n";

  # if rrdtool database doesn't exist, create it
  if (! -e "$rrddir/$_[1].rrd")	{
    print "creating rrd database for $_[1] ...\n";
    RRDs::create "$rrddir/$_[1].rrd",
	"-s 300",
	"DS:in:DERIVE:600:0:12500000",
	"DS:out:DERIVE:600:0:12500000",
	"RRA:AVERAGE:0.5:1:576",
	"RRA:AVERAGE:0.5:6:672",
	"RRA:AVERAGE:0.5:24:732",
	"RRA:AVERAGE:0.5:144:1460";
  }

  # insert values into rrd
  RRDs::update "$rrddir/$_[1].rrd",
	"-t", "in:out",
	"N:$in:$out";

  # create traffic graphs
  &CreateGraph($_[0], "day", $_[1], $_[2]);
  &CreateGraph($_[0], "week", $_[1], $_[2]);
  &CreateGraph($_[0], "month", $_[1], $_[2]); 
  &CreateGraph($_[0], "year", $_[1], $_[2]);
}

sub CreateGraph {
  # creates graph
  # inputs: $_[0]: interface name 
  #	  $_[1]: interval (ie, day, week, month, year)
  #	  $_[2]: interface description 
  #	  $_[3]: Organisation

  RRDs::graph "$imgdir/$_[2]-$_[1].png",
	"-s -1$_[1]",
	"-t traffic on $_[3] :: $_[2]",
	"--lazy",
	"-h", "80", "-w", "500",
	"-l 0",
	"-a", "PNG",
	"-v bytes/sec",
	"DEF:in=$rrddir/$_[2].rrd:in:AVERAGE",
	"DEF:out=$rrddir/$_[2].rrd:out:AVERAGE",
	"CDEF:out_neg=out,-1,*",
	"AREA:in#32CD32:Incoming",
	"LINE1:in#336600",
	"GPRINT:in:MAX:  Max\\: %5.1lf %s",
	"GPRINT:in:AVERAGE: Avg\\: %5.1lf %S",
	"GPRINT:in:LAST: Current\\: %5.1lf %Sbytes/sec\\n",
	"AREA:out_neg#4169E1:Outgoing",
	"LINE1:out_neg#0033CC",
	"GPRINT:out:MAX:  Max\\: %5.1lf %S",
	"GPRINT:out:AVERAGE: Avg\\: %5.1lf %S",
	"GPRINT:out:LAST: Current\\: %5.1lf %Sbytes/sec",
	"HRULE:0#000000";
  if ($ERROR = RRDs::error) {
    print "$0: unable to generate $_[2] $_[1] traffic graph: $ERROR\n";
  }

  # Storing the image in a scalar
  open (IMG, "< $imgdir/$_[2]-$_[1].png");
  binmode(IMG);
  while (<IMG>) {
    $line = $_;
    $imgfile .= $line;
  }
  close(IMG);
  $encodedfile = encode_base64($imgfile);
  $imgfile = "";

  $dbh = DBI->connect($dsn, $pgsql_user, $pgsql_pass)
      or die $DBI::errstr;

  $sql_org = "SELECT id FROM organisations WHERE organisation = '$_[3]'";
  $sth_org = $dbh->prepare($sql_org);
  $execute_result = $sth_org->execute();

  @row_org = $sth_org->fetchrow_array;
  $orgid = $row_org[0];

  $sql_check = "SELECT id FROM rrd WHERE orgid = $orgid AND label = '$_[2]' AND type = '$_[1]'";
  $sth_check = $dbh->prepare($sql_check);
  $execute_result = $sth_check->execute();

  $time = time();
  if ($execute_result == 0) {
    print "Inserting new image!\n";
    $sql = "INSERT INTO rrd (orgid, type, image, label, timestamp) VALUES ($orgid, '$_[1]', '$encodedfile', '$_[2]', $time)";
    print "SQL: $sql\n";
    $sth = $dbh->prepare($sql);
    $execute_result = $sth->execute();
  } else {
    @row_check = $sth_check->fetchrow_array;
    $imgid = $row_check[0];
    print "Updating new image ($imgid)!\n";
    $sql = "UPDATE rrd SET image = '$encodedfile', timestamp = $time WHERE id = $imgid";
    $sth = $dbh->prepare($sql);
    $execute_result = $sth->execute();
  }
  `rm -- $imgdir/$_[2]-$_[1].png`;
}
