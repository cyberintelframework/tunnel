#!/usr/bin/perl

####################################
# PostgreSQL RRD stats             #
# SURFids 3.00                     #
# Changeset 001                    #
# 26-06-2009                       #
# Frits Hoogland                   #
# Modified by Kees Trippelvitz     #
####################################

#####################
# Changelog:
# 001 Initial release
#####################

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
do '/etc/surfnetids/surfnetids-tn.conf';
require "$c_surfidsdir/scripts/tnfunctions.inc.pl";
$servername = "databaseserver";

##################
# Main script
##################

# connect to postgres
dbconnect();

%dbintervals_ar = (
	"d" => "day",
	"w" => "week",
	"m" => "month",
	"y" => "year"
);

sub graph2db {
	
	$label = $_[0];
	$interval = $_[1];
	$servername = $_[2];
	$type = $_[3];
	$file = $_[4];
	$timestamp = time();
	$dbinterval = $dbintervals_ar{$interval};

	open (IMG, "<$file");
	binmode(IMG);
	while ($line = <IMG>) {
		$imgfile .= $line;
	}
	close(IMG);
	$encodedfile = encode_base64($imgfile);
	$imgfile = "";

	$statement = $dbh->prepare("SELECT id FROM serverstats WHERE label = '$label' AND type = '$type' AND interval = '$dbinterval' AND server = '$servername'");
	$result = $statement->execute;

	if ( $result == 0 ) {
		$statement = $dbh->prepare("INSERT INTO serverstats (type, interval, image, label, timestamp, server) VALUES ('$type','$dbinterval','$encodedfile','$label',$timestamp,'$servername')");
		$result = $statement->execute;
	} else {
		@row_check = $statement->fetchrow_array;
		$imgid = $row_check[0];
		$statement = $dbh->prepare("UPDATE serverstats SET image = '$encodedfile', timestamp = $timestamp WHERE id = $imgid");
		$result = $statement->execute;
	}
	`rm $file`;
}
# 
sub PgDatabaseSize {

	# get size
	$statement = $dbh->prepare("SELECT pg_database_size(current_database())");
	$statement->execute;
	$row=$statement->fetchrow;
	$row = $row + 0;

	# create rrd if it doesn't exist
	if (! -e "$c_rrddir/pgdatabasesize.rrd" ) {
		RRDs::create "$c_rrddir/pgdatabasesize.rrd",
			"-s 300",
			"DS:size:GAUGE:600:0:U",
			"RRA:AVERAGE:0.5:1:576",
			"RRA:AVERAGE:0.5:6:672",
			"RRA:AVERAGE:0.5:24:732",
			"RRA:AVERAGE:0.5:144:1460" or die "error creating pgdatabasesize.rrd: " .RRDs::error;
	}

	# insert values into rrd
	RRDs::update "$c_rrddir/pgdatabasesize.rrd","-t","size","N:$row" or die "error writing pgdatabasesize.rrd: " .RRDs::error;

	# generate graph's
	# and insert into database
	foreach ( "d", "w", "m", "y" ) {
		RRDs::graph 
			"$c_imgdir/pgdatabasesize-$_.png",
			"-t","Database size of $c_pgsql_dbname",
			"-s end-1$_",
			"--lazy",
			"-h","80","-w","500",
			"-l","0",
			"-a","PNG",
			"DEF:a=$c_rrddir/pgdatabasesize.rrd:size:AVERAGE",
			"AREA:a#99ff99:Size",
			"GPRINT:a:AVERAGE: %5.1lf %s" or die "error generating graph pgdatabasesize-$_.rrd: " .RRDs::error;
		graph2db( "$c_pgsql_dbname","$_","$servername","pgdatabasesize","$c_imgdir/pgdatabasesize-$_.png" );
	}
}

sub PgTransactions {

	# get commit and rollback number
	$statement = $dbh->prepare("SELECT sum(xact_commit), sum(xact_rollback) FROM pg_stat_database");
	$statement->execute;
	@row=$statement->fetchrow;
        $row[0] = $row[0] + 0;
        $row[1] = $row[1] + 0;

	# create rrd if it doesn't exist
	if (! -e "$c_rrddir/pgtransactions.rrd" ) {
		RRDs::create "$c_rrddir/pgtransactions.rrd",
			"-s 300",
			"DS:xact_commit:COUNTER:600:0:U",
			"DS:xact_rollback:COUNTER:600:0:U",
			"RRA:AVERAGE:0.5:1:576",
			"RRA:AVERAGE:0.5:6:672",
			"RRA:AVERAGE:0.5:24:732",
			"RRA:AVERAGE:0.5:144:1460" or die "error creating pgtransactions.rrd: " .RRDs::error;
	}

	# insert values into rrd
	RRDs::update "$c_rrddir/pgtransactions.rrd","-t","xact_commit:xact_rollback","N:$row[0]:$row[1]" or die "error writing pgtransactions.rrd: " .RRDs::error;

	# generate graph's
	# and insert into database
	foreach ( "d", "w", "m", "y" ) {
		RRDs::graph 
			"$c_imgdir/pgtransactions-$_.png",
			"-t","Transactions of $c_pgsql_dbname",
			"-s end-1$_",
			"--lazy",
			"-h","80","-w","500",
			"-l","0",
			"-a","PNG",
			"-v Number per second",
			"DEF:a=$c_rrddir/pgtransactions.rrd:xact_commit:AVERAGE",
			"DEF:b=$c_rrddir/pgtransactions.rrd:xact_rollback:AVERAGE",
			"AREA:a#99ff99:Commit",
			"GPRINT:a:AVERAGE: %5.1lf\\n",
			"LINE2:b#3300ff:Rollback",
			"GPRINT:b:AVERAGE: %5.1lf" or die "error generating graph pgtransactions-$_.rrd: " .RRDs::error;
		graph2db( "$c_pgsql_dbname","$_","$servername","pgtransactions","$c_imgdir/pgtransactions-$_.png" );
	}
}

sub PgIO {

	# get number of blocks read from filesystem and from cache
	$statement = $dbh->prepare("SELECT sum(blks_read), sum(blks_hit) FROM pg_stat_database");
	$statement->execute;
	@row=$statement->fetchrow;
        $row[0] = $row[0] + 0;
        $row[1] = $row[1] + 0;

	# create rrd if it doesn't exist
	if (! -e "$c_rrddir/pgio.rrd" ) {
		RRDs::create "$c_rrddir/pgio.rrd",
			"-s 300",
			"DS:blks_read:COUNTER:600:0:U",
			"DS:blks_hit:COUNTER:600:0:U",
			"RRA:AVERAGE:0.5:1:576",
			"RRA:AVERAGE:0.5:6:672",
			"RRA:AVERAGE:0.5:24:732",
			"RRA:AVERAGE:0.5:144:1460" or die "error creating pgio.rrd: " .RRDs::error;
	}

	# insert values into rrd
	RRDs::update "$c_rrddir/pgio.rrd","-t","blks_read:blks_hit","N:$row[0]:$row[1]" or die "error writing pgio.rrd: " .RRDs::error;

	# generate graph's
	# and insert into database
	foreach ( "d", "w", "m", "y" ) {
		RRDs::graph 
			"$c_imgdir/pgio-$_.png",
			"-t","Blocks used by $c_pgsql_dbname",
			"-s end-1$_",
			"--lazy",
			"-h","80","-w","500",
			"-l","0","-a","PNG",
			"-v Number per second",
			"DEF:a=$c_rrddir/pgio.rrd:blks_hit:AVERAGE",
			"DEF:b=$c_rrddir/pgio.rrd:blks_read:AVERAGE",
			"AREA:a#99ff99:Read from cache",
			"GPRINT:a:AVERAGE: %5.1lf\\n",
			"LINE2:b#3300ff:Read from filesystem",
			"GPRINT:b:AVERAGE: %5.1lf" or die "error generating graph pgio-$_.rrd: " .RRDs::error;
		graph2db( "$c_pgsql_dbname","$_","$servername","pgio","$c_imgdir/pgio-$_.png" );
	}
}

sub PgScans {

	# get number of scan types
	$statement = $dbh->prepare("SELECT sum(seq_scan), sum(idx_scan) FROM pg_stat_all_tables");
	$statement->execute;
	@row=$statement->fetchrow;
        $row[0] = $row[0] + 0;
        $row[1] = $row[1] + 0;

	# create rrd if it doesn't exist
	if (! -e "$c_rrddir/pgscans.rrd" ) {
		RRDs::create "$c_rrddir/pgscans.rrd",
			"-s 300",
			"DS:seq_scan:COUNTER:600:0:U",
			"DS:idx_scan:COUNTER:600:0:U",
			"RRA:AVERAGE:0.5:1:576",
			"RRA:AVERAGE:0.5:6:672",
			"RRA:AVERAGE:0.5:24:732",
			"RRA:AVERAGE:0.5:144:1460" or die "error creating pgscans.rrd: " .RRDs::error;
	}

	# insert values into rrd
	RRDs::update "$c_rrddir/pgscans.rrd","-t","seq_scan:idx_scan","N:$row[0]:$row[1]" or die "error writing pgscans.rrd: " .RRDs::error;

	# generate graph's
	# and insert into database
	foreach ( "d", "w", "m", "y" ) {
		RRDs::graph 
			"$c_imgdir/pgscans-$_.png",
			"-t","Scans in $c_pgsql_dbname",
			"-s end-1$_",
			"--lazy",
			"-h","80","-w","500",
			"-l","0","-a","PNG",
			"-v Number per second",
			"DEF:a=$c_rrddir/pgscans.rrd:seq_scan:AVERAGE",
			"DEF:b=$c_rrddir/pgscans.rrd:idx_scan:AVERAGE",
			"LINE2:a#3300ff:Table scan",
			"GPRINT:a:AVERAGE: %5.1lf",
			"AREA:b#99ff99:Index scan",
			"GPRINT:b:AVERAGE: %5.1lf\\n" or die "error generating graph pgscan-$_.rrd: " .RRDs::error;
		graph2db( "$c_pgsql_dbname","$_","$servername","pgscans","$c_imgdir/pgscans-$_.png" );
	}
}

sub PgBackends {

	# get total number and number of busy backends
	$statement = $dbh->prepare("SELECT count(*) FROM pg_stat_activity");
	$statement->execute;
	$row_all=$statement->fetchrow;
	$row_all = $row_all + 0;

	$statement = $dbh->prepare("SELECT count(*) FROM pg_stat_activity WHERE current_query <> 'IDLE'");
	$statement->execute;
	$row_busy=$statement->fetchrow;
	$row_busy = $row_busy + 0;

	# create rrd if it doesn't exist
	if (! -e "$c_rrddir/pgbackends.rrd" ) {
		RRDs::create "$c_rrddir/pgbackends.rrd",
			"-s 300",
			"DS:total_backends:GAUGE:600:0:U",
			"DS:busy_backends:GAUGE:600:0:U",
			"RRA:AVERAGE:0.5:1:576",
			"RRA:AVERAGE:0.5:6:672",
			"RRA:AVERAGE:0.5:24:732",
			"RRA:AVERAGE:0.5:144:1460" or die "error creating pgbackends.rrd: " .RRDs::error;
	}

	# insert values into rrd
	RRDs::update "$c_rrddir/pgbackends.rrd","-t","total_backends:busy_backends","N:$row_all:$row_busy" or die "error writing pgbackends.rrd: " .RRDs::error;

	# generate graph's
	# and insert into database
	foreach ( "d", "w", "m", "y" ) {
		RRDs::graph 
			"$c_imgdir/pgbackends-$_.png",
			"-t","Number of backends in $c_pgsql_dbname",
			"-s end-1$_",
			"--lazy",
			"-h","80","-w","500",
			"-l","0",
			"-a","PNG",
			"-v Number",
			"DEF:a=$c_rrddir/pgbackends.rrd:total_backends:AVERAGE",
			"DEF:b=$c_rrddir/pgbackends.rrd:busy_backends:AVERAGE",
			"AREA:a#99ff99:Total backends",
			"GPRINT:a:AVERAGE: %5.1lf\\n",
			"LINE2:b#3300ff:Busy backends",
			"GPRINT:b:AVERAGE: %5.1lf" or die "error generating graph pgbackends-$_.rrd: " .RRDs::error;
		graph2db( "$c_pgsql_dbname","$_","$servername","pgbackends","$c_imgdir/pgbackends-$_.png" );
	}
}
##
# Main
##
PgDatabaseSize;
PgTransactions;
PgIO;
PgScans;
PgBackends;

undef($statement);
$dbh->disconnect();
