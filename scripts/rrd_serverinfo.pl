#!/usr/bin/perl

#########################################
# Server info script                    #
# SURFids 2.04                          #
# Changeset 001                         #
# 14-09-2007                            #
# Hiroshi Suzuki                        #
# Modified by Kees Trippelvitz          #
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

#############################################
# Changelog:
# 001 version 2.00
#############################################

##################
# Modules used
##################
use RRDs;
use DBI;
use MIME::Base64;
use Time::localtime qw(localtime);

##################
# Variables used
##################

# interface
@interface = `ifconfig -a | grep eth | cut -d" " -f1`;
chomp(@interface);

# hdd
@hdd = `df -k | grep -v '^\\(Filesystem\\|tmpfs\\)\\|/mnt' | awk '{ print \$1 }'`;
chomp(@hdd);

if ( -e "/etc/surfnetids/surfnetids-tn.conf" ) {
  do '/etc/surfnetids/surfnetids-tn.conf';
  $servername = "tunnelserver";
}
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
# Main script
##################

# interface
foreach ( @interface ) {
  &ProcessInterface("$_", "$servername");
}

# cpu
&ProcessCPU("cpu", "$servername");

# memory
&ProcessMemory("memory", "$servername");

# hdd
foreach ( @hdd ) {
  &ProcessHDD("$_", "$servername");
}

sub ProcessInterface {
  # process interface
  # inputs: $_[0]: interface name 
  #	  $_[1]: server name

  # get network interface info
  my $in = `ifconfig $_[0] | grep bytes | cut -d":" -f2 | cut -d" " -f1`;
  my $out = `ifconfig $_[0] | grep bytes | cut -d":" -f3 | cut -d" " -f1`;

  $totalin = $totalin += $in;
  $totalout = $totalout += $out;

  # remove eol chars
  chomp($in);
  chomp($out);

#  print "IN2: $in - OUT2: $out\n";
#  print "TOTIN2: $totalin - TOTOUT2: $totalout\n";

  print "$_[0] traffic in, out: $in, $out\n";

  # if rrdtool database doesn't exist, create it
  if (! -e "$c_rrddir/$_[0].rrd")	{
    print "creating rrd database for $_[0] ...\n";
    RRDs::create "$c_rrddir/$_[0].rrd",
	"-s 300",
	"DS:in:DERIVE:600:0:U",
	"DS:out:DERIVE:600:0:U",
	"RRA:AVERAGE:0.5:1:576",
	"RRA:AVERAGE:0.5:6:672",
	"RRA:AVERAGE:0.5:24:732",
	"RRA:AVERAGE:0.5:144:1460";
  }

  # insert values into rrd
  RRDs::update "$c_rrddir/$_[0].rrd",
	"-t", "in:out",
	"N:$in:$out";

  # create traffic graphs
  &CreateGraph($_[0], "day", $_[1], "traffic");
  &CreateGraph($_[0], "week", $_[1], "traffic");
  &CreateGraph($_[0], "month", $_[1], "traffic"); 
  &CreateGraph($_[0], "year", $_[1], "traffic");
}

sub ProcessCPU {
  # process interface
  # inputs: $_[0]: cpu name 
  #	  $_[1]: hostname

  # cpu
  my $cpu = `vmstat 1 2 | tail -1`;
  chomp($cpu);
  my @cpu = split " ", $cpu;
  my $user = $cpu[12];
  my $system = $cpu[13];
  my $idle = $cpu[14];
  my $iowait = $cpu[15];

#  print "$_[0] cpu usage user:$user%, system:$system%, idle:$idle%, iowait:$iowait%\n";

  # if rrdtool database doesn't exist, create it
  if (! -e "$c_rrddir/$_[0].rrd")	{
    print "creating rrd database for cpu ...\n";
    RRDs::create "$c_rrddir/$_[0].rrd",
    	"DS:user:GAUGE:600:0:U",
    	"DS:system:GAUGE:600:0:U",
    	"DS:idle:GAUGE:600:0:U",
    	"DS:iowait:GAUGE:600:0:U",
    	"RRA:AVERAGE:0.5:1:576",
    	"RRA:AVERAGE:0.5:6:672",
    	"RRA:AVERAGE:0.5:24:732",
    	"RRA:AVERAGE:0.5:144:1460",
    	"RRA:MAX:0.5:1:576",
    	"RRA:MAX:0.5:6:672",
    	"RRA:MAX:0.5:24:732",
    	"RRA:MAX:0.5:144:1460";
  }

  # insert values into rrd
  RRDs::update "$c_rrddir/$_[0].rrd",
	"-t", "user:system:idle:iowait",
	"N:$user:$system:$idle:$iowait";

  # create traffic graphs
  &CreateGraph($_[0], "day", $_[1], "cpu");
  &CreateGraph($_[0], "week", $_[1], "cpu");
  &CreateGraph($_[0], "month", $_[1], "cpu"); 
  &CreateGraph($_[0], "year", $_[1], "cpu");
}

sub ProcessHDD {
  # process interface
  # inputs: $_[0]: hdd device name 
  #	  $_[1]: hostname

  # hdd
  my $hdd = `df -k | grep "$_[0]"`;
  chomp($hdd);
  $hdd =~ s/ +/ /g;
  my @hdd = split " ", $hdd;
  $partition = $hdd[5];
  my $use_rate = $hdd[4];
  $use_rate =~ s/%//g;
  my $avail = $hdd[3] * 1024;
  my $used = $hdd[2] * 1024;
  $partition_name = $partition;
  $partition_name =~ s/^\/$/root/;
  $partition_name =~ s/\//_/g;

  # if rrdtool database doesn't exist, create it
  if (! -e "$c_rrddir/$partition_name.rrd")	{
    print "creating rrd database for $partition ...\n";
    RRDs::create "$c_rrddir/$partition_name.rrd",
    	"DS:use_rate:GAUGE:600:0:U",
    	"DS:available:GAUGE:600:0:U",
    	"DS:used:GAUGE:600:0:U",
    	"RRA:AVERAGE:0.5:1:576",
    	"RRA:AVERAGE:0.5:6:672",
    	"RRA:AVERAGE:0.5:24:732",
    	"RRA:AVERAGE:0.5:144:1460",
    	"RRA:MAX:0.5:1:576",
    	"RRA:MAX:0.5:6:672",
    	"RRA:MAX:0.5:24:732",
    	"RRA:MAX:0.5:144:1460";
  }

  # insert values into rrd
  RRDs::update "$c_rrddir/$partition_name.rrd",
	"-t", "use_rate:available:used",
	"N:$use_rate:$avail:$used";

  # create graphs
  &CreateGraph($partition, "day", $_[1], "hdd");
  &CreateGraph($partition, "week", $_[1], "hdd");
  &CreateGraph($partition, "month", $_[1], "hdd"); 
  &CreateGraph($partition, "year", $_[1], "hdd");
}

sub ProcessMemory {
  # process memory
  # inputs: $_[0]: memory 
  #	  $_[1]: hostname

  # memory
  my $memory = `free -b | grep "^Mem:"`;
  chomp($memory);
  $memory =~ s/ +/ /g;
  my @memory = split " ", $memory;
  my $memory_avail = $memory[3];
  my $memory_used = $memory[2];
  my $memory_use_rate = ( $memory_used / ( $memory_used + $memory_avail ) ) * 100;

  my $swap = `free -b | grep "^Swap"`;
  chomp($swap);
  $swap =~ s/ +/ /g;
  my @swap = split " ", $swap;
  my $swap_avail = $swap[3];
  my $swap_used = $swap[2];
  my $swap_use_rate = ( $swap_used / ( $swap_used + $swap_avail ) ) * 100;

  # if rrdtool database doesn't exist, create it
  if (! -e "$c_rrddir/memory.rrd")	{
    print "creating rrd database for memory ...\n";
    RRDs::create "$c_rrddir/memory.rrd",
    	"DS:memory_use_rate:GAUGE:600:0:U",
    	"DS:memory_available:GAUGE:600:0:U",
    	"DS:memory_used:GAUGE:600:0:U",
    	"DS:swap_use_rate:GAUGE:600:0:U",
    	"DS:swap_available:GAUGE:600:0:U",
    	"DS:swap_used:GAUGE:600:0:U",
    	"RRA:AVERAGE:0.5:1:576",
    	"RRA:AVERAGE:0.5:6:672",
    	"RRA:AVERAGE:0.5:24:732",
    	"RRA:AVERAGE:0.5:144:1460",
    	"RRA:MAX:0.5:1:576",
    	"RRA:MAX:0.5:6:672",
    	"RRA:MAX:0.5:24:732",
    	"RRA:MAX:0.5:144:1460";
  }

  # insert values into rrd
  RRDs::update "$c_rrddir/memory.rrd",
	"-t", "memory_use_rate:memory_available:memory_used:swap_use_rate:swap_available:swap_used",
	"N:$memory_use_rate:$memory_avail:$memory_used:$swap_use_rate:$swap_avail:$swap_used";

  # create graphs
  &CreateGraph("", "day", $_[1], "memory");
  &CreateGraph("", "week", $_[1], "memory");
  &CreateGraph("", "month", $_[1], "memory"); 
  &CreateGraph("", "year", $_[1], "memory");
}

sub CreateGraph {
  # creates graph
  # inputs: $_[0]: cpu, interface name, partition 
  #	  $_[1]: interval (ie, day, week, month, year)
  #	  $_[2]: server name
  #	  $_[3]: Type (ie, cpu, hdd, traffic, memory)

  if ( $_[3] eq "cpu" ) {
	$pngname="$_[2]-$_[0]-$_[1]";
	$pngfilename="$pngname.png";
	RRDs::graph "$c_imgdir/$pngfilename",
		"-s -1$_[1]",
		"-t cpu usage on $servername",
		"--lazy",
		"-h", "100", "-w", "500",
		"-l 0",
		"-a", "PNG",
		"-v CPU Utilization(%)",
		"-u 100",
		"--rigid",
		"DEF:a=$c_rrddir/$_[0].rrd:user:AVERAGE",
		"DEF:b=$c_rrddir/$_[0].rrd:system:AVERAGE",
		"DEF:c=$c_rrddir/$_[0].rrd:iowait:AVERAGE",
		"DEF:d=$c_rrddir/$_[0].rrd:idle:AVERAGE",
		"CDEF:all=a,b,c,d,+,+,+",
		"CDEF:unknown=all,UN,INF,UNKN,IF",
		"AREA:d#99ff99:idle",
		"GPRINT:d:LAST:  Cur\\:%3.0lf%%",
		"GPRINT:d:AVERAGE: Avg\\:%3.0lf%%",
		"GPRINT:d:MAX: Max\\:%3.0lf%%",
		"STACK:a#eacc00:user",
		"GPRINT:a:LAST:  Cur\\:%3.0lf%%",
		"GPRINT:a:AVERAGE: Avg\\:%3.0lf%%",
		"GPRINT:a:MAX: Max\\:%3.0lf%%\\n",
		"STACK:b#ff77ff:system",
		"GPRINT:b:LAST:Cur\\:%3.0lf%%",
		"GPRINT:b:AVERAGE: Avg\\:%3.0lf%%",
		"GPRINT:b:MAX: Max\\:%3.0lf%%",
		"STACK:c#ff3932:iowait",
		"GPRINT:c:LAST:  Cur\\:%3.0lf%%",
		"GPRINT:c:AVERAGE: Avg\\:%3.0lf%%",
		"GPRINT:c:MAX: Max\\:%3.0lf%%\\n",
		"AREA:unknown#777777:unknown";
  }

  if ( $_[3] eq "hdd" ) {
	$pngname="$_[2]-$_[3]-$partition_name-$_[1]";
	$pngfilename="$pngname.png";
	RRDs::graph "$c_imgdir/$pngfilename",
		"-s -1$_[1]",
		"-t available $partition partition on $servername",
		"--lazy",
		"-h", "100", "-w", "500",
		"-l 0",
		"-a", "PNG",
		"-v Available(Byte)",
		"--rigid",
		"DEF:a=$c_rrddir/$partition_name.rrd:use_rate:AVERAGE",
		"DEF:b=$c_rrddir/$partition_name.rrd:available:AVERAGE",
		"DEF:c=$c_rrddir/$partition_name.rrd:used:AVERAGE",
		"CDEF:all=a,b,c,+,+",
		"CDEF:unknown=all,UN,INF,UNKN,IF",
		"AREA:b#99ff99:available",
		"GPRINT:b:LAST:\\: %4.2lf%sB ",
		"STACK:c#ff99ff:used",
		"GPRINT:c:LAST:\\: %4.2lf%sB ",
		"GPRINT:a:LAST: usage rate \\: %3.0lf%%  ",
		"AREA:unknown#777777:unknown";
  }

  if ( $_[3] eq "memory" ) {
	$pngname="$_[2]-memory-$_[1]";
	$pngfilename="$pngname.png";
	RRDs::graph "$c_imgdir/$pngfilename",
		"-s -1$_[1]",
		"-t memory and swap usage on $servername",
		"--lazy",
		"-h", "100", "-w", "500",
		"-l 0",
		"-a", "PNG",
		"-v Usage(Byte)",
		"--rigid",
		"DEF:a=$c_rrddir/memory.rrd:memory_use_rate:AVERAGE",
		"DEF:b=$c_rrddir/memory.rrd:memory_available:AVERAGE",
		"DEF:c=$c_rrddir/memory.rrd:memory_used:AVERAGE",
		"DEF:d=$c_rrddir/memory.rrd:swap_use_rate:AVERAGE",
		"DEF:e=$c_rrddir/memory.rrd:swap_available:AVERAGE",
		"DEF:f=$c_rrddir/memory.rrd:swap_used:AVERAGE",
		"CDEF:all=a,b,c,d,e,f,+,+,+,+,+",
		"CDEF:unknown=all,UN,INF,UNKN,IF",
		"AREA:b#99ff99:memory available",
		"GPRINT:b:LAST:\\: %4.2lf%sB ",
		"STACK:c#ff99ff:memory used",
		"GPRINT:c:LAST:\\: %4.2lf%sB ",
		"GPRINT:a:LAST: memory usage rate \\: %3.0lf%%\\n",
		"STACK:e#99ffff:swap available",
		"GPRINT:e:LAST:\\: %4.2lf%sB ",
		"STACK:f#ff9999:swap used",
		"GPRINT:f:LAST:\\: %4.2lf%sB ",
		"GPRINT:d:LAST: swap usage rate \\: %3.0lf%%  ",
		"AREA:unknown#777777:unknown";
  }

  if ( $_[3] eq "traffic" ) {
	$pngname="$_[2]-$_[0]-$_[1]";
	$pngfilename="$pngname.png";
	RRDs::graph "$c_imgdir/$pngfilename",
		"-s -1$_[1]",
		"-t traffic $_[0] on $servername",
		"--lazy",
		"-h", "80", "-w", "500",
		"-l 0",
		"-a", "PNG",
		"-v bytes/sec",
		"DEF:in=$c_rrddir/$_[0].rrd:in:AVERAGE",
		"DEF:out=$c_rrddir/$_[0].rrd:out:AVERAGE",
		"CDEF:unknown=in,UN,INF,UNKN,IF",
		"CDEF:out_neg=out,-1,*",
		"CDEF:unknown_out=out,UN,INF,UNKN,IF",
		"AREA:in#32CD32:Incoming",
		"LINE1:in#336600",
		"GPRINT:in:MAX:  Max\\: %5.1lf %s",
		"GPRINT:in:AVERAGE: Avg\\: %5.1lf %S",
		"GPRINT:in:LAST: Current\\: %5.1lf %Sbytes/sec",
		"AREA:unknown#777777:unknown\\n",
		"AREA:out_neg#4169E1:Outgoing",
		"LINE1:out_neg#0033CC",
		"GPRINT:out:MAX:  Max\\: %5.1lf %S",
		"GPRINT:out:AVERAGE: Avg\\: %5.1lf %S",
		"GPRINT:out:LAST: Current\\: %5.1lf %Sbytes/sec",
		"AREA:unknown_out#777777:unknown",
		"HRULE:0#000000";
  }

  if ($ERROR = RRDs::error) {
    print "$0: unable to generate $_[2] $_[0] traffic graph: $ERROR\n";
  }

  # inputs: $_[0]: cpu, interface name, partition 
  #	  $_[1]: interval (ie, day, week, month, year)
  #	  $_[2]: server name
  #	  $_[3]: Type (ie, cpu, hdd, traffic, memory)

  &RegistDB($_[0], $_[1], $_[2], $_[3], $pngfilename);

}

sub RegistDB {
  $label = $_[0];
  $interval = $_[1];
  $servername = $_[2];
  $type = $_[3];
  $file = $_[4];

  $timestamp = time();

  # Storing the image in a scalar
  open (IMG, "< $c_imgdir/$file");
  binmode(IMG);
  while (<IMG>) {
    $line = $_;
    $imgfile .= $line;
  }
  close(IMG);
  $encodedfile = encode_base64($imgfile);
  $imgfile = "";

  if ($dbh) {
    $dbh = "";
  }
  $checkdb = connectdb();
  $sql_check = "SELECT id FROM serverstats WHERE label = '$label' AND type = '$type' AND interval = '$interval' AND server = '$servername'"; 
  $sth_check = $dbh->prepare($sql_check);
  $execute_result = $sth_check->execute();

  if ($execute_result == 0) {
    print "Inserting new image!\n";
    $sql = "INSERT INTO serverstats (type, interval, image, label, timestamp, server) ";
    $sql .= "VALUES ('$type', '$interval', '$encodedfile', '$label', $timestamp, '$servername')";
    $sth = $dbh->prepare($sql);
    $execute_result = $sth->execute();
  } else {
    @row_check = $sth_check->fetchrow_array;
    $imgid = $row_check[0];
    print "Updating new image ($imgid)!\n";
    $sql = "UPDATE serverstats SET image = '$encodedfile', timestamp = $timestamp WHERE id = $imgid";
    $sth = $dbh->prepare($sql);
    $execute_result = $sth->execute();
  }
  $dbh = "";
  `rm $c_imgdir/$file`;
}
