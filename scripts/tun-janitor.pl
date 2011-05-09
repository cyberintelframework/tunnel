#!/usr/bin/perl

##################
# Includes
##################
do '/etc/surfnetids/surfnetids-tn.conf';
require "$c_surfidsdir/scripts/tnfunctions.inc.pl";

our $source = 'tun-janitor.pl';
our $sensor = 'unkown';
our $tap = 'unknown';
our $remoteip = '0.0.0.0';
our $pid = $$;
our $g_vlanid = 0;

##################
# Modules used
##################
use DBI;
use Time::localtime qw(localtime); 

##################
# Main script
##################

$result = dbconnect();
if ($result eq 'false') {
    print "No database connection";
    exit(6);
}

$sql = "SELECT arp, dhcp, ipv6, protos, keyname, vlanid, tap, id FROM sensors WHERE status > 0 AND NOT status IN (3, 6)";
$res = dbquery($sql);

while (@row = $res->fetchrow_array) {
    $arp = $row[0];
    $dhcp = $row[1];
    $ipv6 = $row[2];
    $protos = $row[3];
    $keyname = $row[4];
    $vlanid = $row[5];
    $tap = $row[6];
    $sid = $row[7];

    $chkif = getifip($tap);

    if ($c_enable_pof == 1) {
        $chk = `ps -ef | grep p0f | grep -v grep | grep " $tap " | wc -l`;
        chomp($chk);
        if ($chk == 0) {
            if ("$chkif" ne "false") {
                system "p0f -d -i $tap -o /dev/null";
            }
        }
    }
    if ($c_ethernet_module == 1) {
        # Check for ethernet modules
        if ($arp == 1 || $dhcp == 1 || $ipv6 == 1 || $protos == 1) {
            $chk = `ps -ef | grep detectarp | grep -v grep | grep " $tap " | wc -l`;
            chomp($chk);
            if ($chk == 0) {
                if ("$chkif" ne "false") {
                    system("$c_surfidsdir/scripts/detectarp.pl $tap $sid &");
                }
            }
        }
    }
}
