#!/usr/bin/perl

sub getAge {
	$file = $_[0];
	$posix = $_[1];
	$ts = (stat($file))[9];
	$diff = time() - $ts;
	$days = $diff / (3600 * 24);
	if ($posix == 1) {
	        $days = floor($days);
	}
}

##################
# Modules used
##################
use DBI;

##################
# Variables used
##################
do '/etc/surfnetids/surfnetids-tn.conf';
require "$c_surfidsdir/scripts/tnfunctions.inc.pl";

##################
# Main
##################

sub getMethod {
	@methods = ("apt-cache", "dpkg", "rpm");
	foreach $m (@methods) {
		$loc = `whereis $m | awk '{print \$2}'`;
		chomp($loc);
		if ("$loc" ne "") {
			if (-x "$loc") {
				return ($m, $loc);
			}
		}
	}	
}

my ($p_method, $p_loc) = getMethod();

# PERL CHECKS
######################
# Location
$loc = `whereis perl | awk '{print \$2}'`;
chomp($loc);
print "[Perl] Binary location: \t\t $loc\n";

# Version
($major,$minor,$patch) = $] =~ /(\d+)\.(\d{3})(\d{3})/;
$minor = $minor + 0;
$patch = $patch + 0; 
print "[Perl] Version: \t\t\t $major.$minor.$patch\n";

# Modules
unless (eval "require MIME::Base64") {
	print "[Perl] Module MIME::Base64: \t\t Failed\n";
} else {
	print "[Perl] Module MIME::Base64: \t\t OK\n";
}

unless (eval "require RRDs") {
	print "[Perl] Module RRDs: \t\t\t Failed\n";
} else {
	print "[Perl] Module RRDs: \t\t\t OK\n";
}

unless (eval "require Socket") {
	print "[Perl] Module Socket: \t\t\t Failed\n";
} else {
	print "[Perl] Module Socket: \t\t\t OK\n";
}

unless (eval "require Net::PcapUtils") {
	print "[Perl] Module Net::PcapUtils: \t\t Failed\n";
} else {
	print "[Perl] Module Net::PcapUtils: \t\t OK\n";
}

unless (eval "require Net::DHCP::Constants") {
	print "[Perl] Module Net::DHCP::Constants: \t Failed\n";
} else {
	print "[Perl] Module Net::DHCP::Constants: \t OK\n";
}

unless (eval "require Net::DHCP::Packet") {
	print "[Perl] Module Net::DHCP::Packet: \t Failed\n";
} else {
	print "[Perl] Module Net::DHCP::Packet: \t OK\n";
}

unless (eval "require Net::Pcap") {
	print "[Perl] Module Net::Pcap: \t\t Failed\n";
} else {
	print "[Perl] Module Net::Pcap: \t\t OK\n";
}

unless (eval "require NetPacket::IGMP") {
	print "[Perl] Module NetPacket::IGMP: \t\t Failed\n";
} else {
	print "[Perl] Module NetPacket::IGMP: \t\t OK\n";
}

unless (eval "require NetPacket::IP") {
	print "[Perl] Module NetPacket::IP: \t\t Failed\n";
} else {
	print "[Perl] Module NetPacket::IP: \t\t OK\n";
}

unless (eval "require NetPacket::IPv6") {
	print "[Perl] Module NetPacket::IPv6: \t\t Failed\n";
} else {
	print "[Perl] Module NetPacket::IPv6: \t\t OK\n";
}

unless (eval "require NetPacket::TCP") {
	print "[Perl] Module NetPacket::TCP: \t\t Failed\n";
} else {
	print "[Perl] Module NetPacket::TCP: \t\t OK\n";
}

unless (eval "require NetPacket::UDP") {
	print "[Perl] Module NetPacket::UDP: \t\t Failed\n";
} else {
	print "[Perl] Module NetPacket::UDP: \t\t OK\n";
}

unless (eval "require NetPacket::Ethernet") {
	print "[Perl] Module NetPacket::Ethernet: \t Failed\n";
} else {
	print "[Perl] Module NetPacket::Ethernet: \t OK\n";
}

unless (eval "require NetPacket::ARP") {
	print "[Perl] Module NetPacket::ARP: \t\t Failed\n";
} else {
	print "[Perl] Module NetPacket::ARP: \t\t OK\n";
}

unless (eval "require NetPacket::ICMP") {
	print "[Perl] Module NetPacket::ICMP: \t\t Failed\n";
} else {
	print "[Perl] Module NetPacket::ICMP: \t\t OK\n";
}

unless (eval "require Net::SMTP") {
	print "[Perl] Module Net::SMTP: \t\t Failed\n";
} else {
	print "[Perl] Module Net::SMTP: \t\t OK\n";
}

unless (eval "require MIME::Lite") {
	print "[Perl] Module MIME::Lite: \t\t Failed\n";
} else {
	print "[Perl] Module MIME::Lite: \t\t OK\n";
}

unless (eval "require GnuPG") {
	print "[Perl] Module GnuPG: \t\t\t Failed\n";
} else {
	print "[Perl] Module GnuPG: \t\t\t OK\n";
}

unless (eval "require POSIX") {
	print "[Perl] Module POSIX: \t\t\t Failed\n";
	$posix = 0;
} else {
	print "[Perl] Module POSIX: \t\t\t OK\n";
	use POSIX qw(floor);
	$posix = 1;
}

# DB CHECKS
######################
# Connection
eval {
	$dbh = DBI->connect($c_dsn, $c_pgsql_user, $c_pgsql_pass, {RaiseError => 1});
};
if ($@) {
	print "[Database] Connection: \t\t\t " .$DBI::errstr . "\n";
} else {
	print "[Database] Connection: \t\t\t OK\n";
}

# Version
$r = dbquery("SELECT * FROM version");
@row = $r->fetchrow_array;
print "[Database] Schema version: \t\t " .$row[0]. "\n";

# PHP
######################
# Location
$loc = `whereis php | awk '{print \$2}'`;
chomp($loc);
if ("$loc" ne "") {
	print "[PHP] Binary location: \t\t\t $loc\n";
}

# Version
$ver = "";
if ($loc =~ /^\/.*php$/) {
	$ver = `$loc -v | head -n1`;
	chomp($ver);
	print "[PHP] Version: \t\t\t\t $ver\n";
} else {
	if ("$p_method" eq "apt-cache") {
		$ver = `$p_loc policy php5 | grep "Installed" | awk '{print \$2}'`;
		chomp($ver);
		print "[PHP] Version: \t\t\t\t $ver\n";
	} elsif ("$p_method" eq "dpkg") {
		$ver = `$p_loc -l | sed -e 's/^ii  //' | grep "^php5 " | awk '{print \$2}'`;
		chomp($ver);
		print "[PHP] Version: \t\t\t\t $ver\n";
	} elsif ("$p_method" eq "rpm") {
		$ver = `rpm -qa | grep "php-5" | sed 's/php-//'`;
		chomp($ver);
		print "[PHP] Version: \t\t\t\t $ver\n";
	}
}

# Openvpn
######################
# openvpn
$loc = `whereis openvpn | awk '{print \$2}'`;
chomp($loc);
print "[OpenVPN] Binary location: \t\t $loc\n";

if ("$p_method" eq "apt-cache") {
	$ver = `$p_loc policy openvpn | grep "Installed" | awk '{print \$2}'`;
	chomp($ver);
	print "[OpenVPN] Version: \t\t\t $ver\n";
} elsif ("$p_method" eq "dpkg") {
	$ver = `$p_loc -l | sed -e 's/^ii  //' | grep "^openvpn " | awk '{print \$2}'`;
	chomp($ver);
	print "[OpenVPN] Version: \t\t\t $ver\n";
} elsif ("$p_method" eq "rpm") {
	$ver = `rpm -qa | grep "openvpn" | sed 's/openvpn-//'`;
	chomp($ver);
	print "[OpenVPN] Version: \t\t\t $ver\n";
}

if ("$p_method" ne "rpm") {
	if ("$ver" ne "") {
		if ($ver !~ /^2\.[1-9]\.[3-9]-[4-9].*/) {
			if ($ver !~ /^2\.[1-9].*rc.*/) {
				if ("$ver" !~ /^2\.0.*/) {
					print '[OpenVPN] Bug: '."\t\t\t\t".' Possibly affected by Debian bug #574164 (See FAQ T36 on the IDS webpage)'."\n";
				}
			}
		}
	}
}
if ("$ver" =~ /^2\.0.*/) {
	print "[OpenVPN] Warning: \t\t\t Your OpenVPN version is too old. Upgrade to 2.1 or higher\n";
}

# Certificates
######################
# server.crt
$chk = `openssl verify -CAfile $c_surfidsdir/serverkeys/ca.crt $c_surfidsdir/serverkeys/tunserver.crt | awk '{print \$2}'`;
chomp($chk);
print "[server.crt] Verification: \t\t $chk\n";

$chk = `openssl x509 -in $c_surfidsdir/serverkeys/tunserver.crt -text | grep "Subject:" | sed -e 's/Subject: //'`;
chomp($chk);
print "[server.crt] Subject: \t\t $chk\n";

# INFO
######################
# OUI
$file = $c_surfidsdir . "/scripts/oui.txt";
if (-e $file) {
	$age = getAge($file, $posix);
	print "[GeoIP] Age data file: \t\t\t $age days\n";
}
