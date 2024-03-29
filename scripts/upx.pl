#!/usr/bin/perl

####################################
# UPX detection script             #
# SURFids 3.00                     #
# Changeset 001                    #
# 08-05-2009                       #
# Kees Trippelvitz                 #
####################################

# NOTE: This script is still considered beta and thus not actively called 
# from the scanbinaries script or anywhere else.

#####################
# Changelog:
# 001 version 3.00 release
#####################

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

our $source = 'upx.pl';
our $sensor = 'unkown';
our $tap = 'unknown';;
our $remoteip = '0.0.0.0';
our $pid = $$;
our $g_vlanid = 0;

$res = dbconnect();
if ($res eq 'false') {
    print "No database connection!\n";
    exit(1);
}

#opendir BINDIR, $c_bindir;
#@files = grep !/^\.\.?$/, readdir BINDIR;

if ("$ARGV[0]" ne "") {
    @notscanned = @ARGV;
} else {
    $sth = dbquery("SELECT name FROM uniq_binaries, binaries_detail WHERE binaries_detail.bin = uniq_binaries.id AND binaries_detail.upx IS NULL");
    while (@row = $sth->fetchrow_array) {
        $file = $row[0];
        push(@notscanned, $file);
    }
}

if (scalar(@notscanned) == 0) {
    print "No files to scan, exiting!\n";
    logsys($f_log_warn, "SCAN_LOG", "No files to scan, exiting");
    exit 0;
}

#############
# UPX
#############
# Check the UPX result and add it if necessary
if ($c_scan_upx == 1) {
    $i = 0;
    foreach $file (@notscanned) {
        $filepath = "$c_bindir/$file";
        if (-e $filepath) {
            $result = `upx -t $filepath 2>&1 | grep '\\b$file\\b'`;
            $info = parse_upx($result);
            print "$file -> $info\n";

            # Get the binary ID
            $sth = dbquery("SELECT id FROM uniq_binaries WHERE name = '$file'");
            @row = $sth->fetchrow_array;
            $binid = $row[0];

            # Check for binary detail record
            $num = dbnumrows("SELECT id FROM binaries_detail WHERE bin = $binid");
            if ($num != 0) {
                $res = dbquery("UPDATE binaries_detail SET upx = '$info' WHERE bin = $binid");
                $i++;
            } else {
                print "ERR: No database record for $file!\n";
            }
        } else {
            print "$file does not exist, skipping!\n";
        }
    }
    logsys($f_log_debug, "SCAN_RESULT", "Updated $i records");
    print "Updated $i records!\n";
}

