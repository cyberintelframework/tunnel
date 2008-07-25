#!/usr/bin/perl

#########################################
# Management of OpenVPN                 #
# SURFids 2.10.00                       #
# Changeset 002                         #
# 18-06-2008                            #
# Jan van Lith & Kees Trippelvitz       #
#########################################

################
# Changelog:
# 002 Fixed port calculation
# 001 Initial release
################

use Time::localtime qw(localtime);
use IO::Socket;

$basedir = "/cdrom/scripts";
do "$basedir/sensor.conf";
do "$basedir/network_if.conf";
require "$basedir/functions.inc.pl";

$tunnel = $ARGV[0];

$port = 1000 + $tunnel;
print "PORT: $port\n";

# Opening socket
my $sock = new IO::Socket::INET (
			PeerAddr => '127.0.0.1',
			PeerPort => $port,
			Proto => 'tcp',
);
unless (defined($sock)) {
	print "Error connecting to host!\n";
	exit;
}
print "SOCK: $sock\n";
$sock->autoflush(1);
die "Can't fork!: $!" unless defined($kidpid = fork());

print "KIDPID: $kidpid\n";

if ($kidpid) {
  # Printing stuff
  while (defined ($line = <$sock>)) {
    print STDOUT $line;
  }
} else {
  while (defined ($line = <STDIN>)) {
    print $sock $line;
  }
}
$sock->close();
