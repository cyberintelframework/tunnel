#!/usr/bin/perl

########################################
# ARP detection module                       
# SURFnet IDS                          
# Version 2.10.01                      
# 15-02-2007                           
# Kees Trippelvitz & Jan van Lith
########################################

#########################################################################################
# Copyright (C) 2005 SURFnet                                                            #
# Author Kees Trippelvitz & Jan van Lith                                                #
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

#####################
# Changelog:
# 2.10.01 Ignore checking the gateway if it is not in the local network range
# 2.00.02 Added dhcp alerts
# 2.00.01 Initial release
#####################

##################
# Modules used
##################
require Net::Pcap;
use Net::PcapUtils;
use Net::DHCP::Packet;
use Net::DHCP::Constants;
use NetPacket::IP;
use NetPacket::TCP;
use NetPacket::UDP;
use NetPacket::Ethernet;
use NetPacket::ARP;
use NetPacket::ICMP;
use NetPacket::IGMP;
use DBI;
use Time::localtime qw(localtime);
use POSIX;
use Socket;
use Net::SMTP;
use MIME::Lite;
use GnuPG qw( :algo );
#use NetPacket::Ethernet qw(:types);
#use NetPacket::Ethernet qw(:strip);
#use NetPacket::IP qw(:strip);

##################
# Variables used
##################
do '/etc/surfnetids/surfnetids-tn.conf';
require "$c_surfidsdir/scripts/tnfunctions.inc.pl";
$tap = $ARGV[0];

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
  if ( ! -d "$c_surfidsdir/log/$day$month$year/$tap" ) {
    mkdir("$c_surfidsdir/log/$day$month$year/$tap");
  }
  $logfile = "$c_surfidsdir/log/$day$month$year/$tap/$logfile";
} else {
  $logfile = "$c_surfidsdir/log/$logfile";
}

$argcount = @ARGV;
if ($argcount == 0) {
  exit 1;
}

##################
# Data sets
##################
require "$c_surfidsdir/scripts/types_data.pl";

##################
# Main script
##################

$ts = time();

# Connect to the database (dbh = DatabaseHandler or linkserver)
$dbconn = connectdb();

# Getting the sensor ID
if ("$dbconn" ne "false") {
  $sql = "SELECT id, organisation, netconf, netconfdetail FROM sensors WHERE tap = '$tap'";
  $sth = $dbh->prepare($sql);
  $er = $sth->execute();

  @row = $sth->fetchrow_array;
  $sensorid = $row[0];
  $org = $row[1];
  $netconf = $row[2];
  $netconfdet = $row[3];
  if ("$sensorid" eq "") {
    exit 1;
  }
  if ("$org" eq "") {
    exit 1;
  }
} else {
  exit 1;
}

# Getting admin organisation ID
$sql = "SELECT id FROM organisations WHERE organisation = 'ADMIN'";
$sth = $dbh->prepare($sql);
$er = $sth->execute();

@row = $sth->fetchrow_array;
$admin_org = $row[0];

%arp_mail = ();
# Get the info needed for the mailreport stuff [ARP]
$sql = "SELECT login.email, login.gpg, report_content.sensor_id, report_content.id FROM report_content, login ";
$sql .= " WHERE login.id = report_content.user_id AND report_content.template = 5 AND report_content.active = TRUE ";
$sql .= " AND (report_content.sensor_id = $sensorid OR (report_content.sensor_id = -1 AND (login.organisation = $org OR login.organisation = $admin_org)))";
$sth = $dbh->prepare($sql);
$er = $sth->execute();

while (@row = $sth->fetchrow_array) {
  $email = $row[0];
  $gpg = $row[1];
  $db_sid = $row[2];
  $rcid = $row[3];
  if ("$db_sid" eq "-1" || "$db_sid" eq "$sensorid") {
    $arp_mail{"$email"} = "$gpg-$rcid";
  }
}

%dhcp_mail = ();
# Get the info needed for the mailreport stuff [DHCP]
$sql = "SELECT login.email, login.gpg, report_content.sensor_id, report_content.id FROM report_content, login ";
$sql .= " WHERE login.id = report_content.user_id AND report_content.template = 7 AND report_content.active = TRUE ";
$sql .= " AND (report_content.sensor_id = $sensorid OR (report_content.sensor_id = -1 AND (login.organisation = $org OR login.organisation = $admin_org)))";
$sth = $dbh->prepare($sql);
$er = $sth->execute();

while (@row = $sth->fetchrow_array) {
  $email = $row[0];
  $gpg = $row[1];
  $db_sid = $row[2];
  $rcid = $row[3];
  if ("$db_sid" eq "-1" || "$db_sid" eq "$sensorid") {
    $dhcp_mail{"$email"} = "$gpg-$rcid";
  }
}
$mail_refresh = $ts + $c_mail_refresh;

# Initialize the scripts arp cache, alert and static hashes
%arp_cache = ();
%arp_alert = ();
%arp_static = ();
%sniff_protos_eth = ();
%sniff_protos_ip = ();
%sniff_protos_icmp = ();
%sniff_protos_igmp = ();

#### ARP CACHE ####
# Filling the local scripts arp cache
$sql = "SELECT mac, ip FROM arp_cache WHERE sensorid = $sensorid";
$sth = $dbh->prepare($sql);
$er = $sth->execute();

while (@row = $sth->fetchrow_array) {
  $db_mac = $row[0];
  $db_ip = $row[1];
  $arp_cache{"$db_mac"} = $db_ip;
}
$ts = time();
$cache_refresh = $ts + $c_arp_cache_refresh;

#### ARP STATIC ####
# Filling the local scripts static arp list
$sql = "SELECT mac, ip FROM arp_static, sniff_hosttypes WHERE arp_static.id = sniff_hosttypes.staticid AND sniff_hosttypes.type = 1 AND arp_static.sensorid = $sensorid";
$sth = $dbh->prepare($sql);
$er = $sth->execute();

while (@row = $sth->fetchrow_array) {
  $db_mac = $row[0];
  $db_ip = $row[1];
  $arp_static{"$db_ip"} = $db_mac;
}
$ts = time();
$static_refresh = $ts + $c_arp_static_refresh;

#### DHCP STATIC ####
# Filling the local scripts static dhcp server list
$sql = "SELECT mac, ip FROM arp_static, sniff_hosttypes WHERE arp_static.id = sniff_hosttypes.staticid AND sniff_hosttypes.type = 2 AND arp_static.sensorid = $sensorid";
$sth = $dbh->prepare($sql);
$er = $sth->execute();

while (@row = $sth->fetchrow_array) {
  $db_mac = $row[0];
  $db_ip = $row[1];
  $dhcp_static{"$db_ip"} = $db_mac;
}
$ts = time();
$dhcp_refresh = $ts + $c_dhcp_static_refresh;

#### SNIFF PROTOS ####
refresh_protos(0);
refresh_protos(1);
refresh_protos(11);
refresh_protos(12);
refresh_protos(11768);

$ts = time();
$protos_refresh = $ts + $c_sniff_protos_refresh;

##################
# Getting interface info
##################
$ifip = getifip($tap);
$ifmask = getifmask($tap);
$ifmin = ip2long(network($ifip, $ifmask));
$ifmax = ip2long(bc($ifip, $ifmask));
if ("$netconf" eq "dhcp" || "$netconf" eq "vland") {
  $gw = `cat /var/lib/dhcp3/$tap.leases | grep routers | tail -n1 | awk '{print \$3}' | awk -F\\; '{print \$1}'`;
  chomp($gw);
  if ("$gw" eq "") {
    $gw = gw($ifip, $ifmask);
  }
} elsif ("$netconf" eq "static" || "$netconf" eq "vlans") {
  @netconf_ar = split(/\|/, $netconfdet);
  $gw = $netconf_ar[1];
}
if ("$gw" eq "") {
  $gw = gw($ifip, $ifmask);
}

#print "GW: $gw\n";

##################
# Checking the gateway IP/MAC pair.
##################

$sql = "SELECT mac FROM arp_static WHERE sensorid = $sensorid AND ip = '$gw'";
$sth = $dbh->prepare($sql);
$er = $sth->execute();
@row = $sth->fetchrow_array;
$db_mac = $row[0];

`arping -h 2>/dev/null`;
$arpec = $?;
$gwlong = ip2long($gw);
if ($gwlong < $ifmin && $gwlong > $ifmax) {
  $arpec == 1;
}
if ($arpec == 0) {
  %maclist = ();
  open(ARPING, "arping -r -i $tap -c 4 $gw | ");
  while (<ARPING>) {
    $mac = $_;
    chomp($mac);
    $maclist{"$mac"} = 0;
  }
  close(ARPING);
  $count = keys(%maclist);
  if ($count == 1) {
    if ("$db_mac" eq "") {
      # Static ARP entry for the gateway not yet present. Add it.

      $sql = "INSERT INTO arp_static (mac, ip, sensorid) VALUES ('$mac', '$gw', $sensorid)";
      $sth = $dbh->prepare($sql);
      $er = $sth->execute();

      $sql = "SELECT id FROM arp_static WHERE mac = '$mac' AND ip = '$gw' AND sensorid = '$sensorid'";
      $sth = $dbh->prepare($sql);
      $er = $sth->execute();
      @row = $sth->fetchrow_array;
      $staticid = $row[0];

      $sql = "INSERT INTO sniff_hosttypes (staticid, type) VALUES ('$staticid', '1')";
      $sth = $dbh->prepare($sql);
      $er = $sth->execute();
    } elsif ("$db_mac" ne "$mac") {
      # Static ARP entry for the gateway present, but with a different MAC address. Update it.

      $sql = "UPDATE arp_static SET mac = '$mac' WHERE sensorid = $sensorid AND ip = '$gw'";
      $sth = $dbh->prepare($sql);
      $er = $sth->execute();
    }
  } else {
    # Gateway returned multiple MAC addresses. Network is possibly poisoned!
    if ("$db_mac" ne "") {
      # Static ARP entry present in the database.
      if (exists $maclist{"$db_mac"}) {
        for my $key ( keys %maclist ) {
          if ("$key" ne "$db_mac") {
            $poisonmac = $key;
            add_arp_alert($db_mac, $poisonmac, $gw, $gw, $sensorid);
          }
        }
      }
    }
  }
}

##################
# Checking the DHCP server IP/MAC pair.
##################


#if ("$netconf" eq "dhcp" || "$netconf" eq "vland") {
#  $dhcpserver = `cat /var/lib/dhcp3/$tap.leases | grep dhcp-server-identifier | tail -n1 | awk '{print \$3}' | awk -F\\; '{print \$1}'`;
#  chomp($dhcpserver);

#  print "DHCP SERVER: $dhcpserver\n";

#  %maclist = ();
#  open(ARPING, "arping -r -i $tap -c 2 $dhcpserver | ");
#  while (<ARPING>) {
#    $mac = $_;
#    chomp($mac);
#    $maclist{"$mac"} = 0;
#  }
#  close(ARPING);
#  $count = keys(%maclist);
#  print "arping -r -i $tap -c 2 $dhcpserver\n";
#  print "COUNT: $count\n";
#  if ($count == 1) {
#    $sql = "SELECT id, mac FROM arp_static WHERE sensorid = $sensorid AND ip = '$dhcpserver'";
#    $sth = $dbh->prepare($sql);
#    $er = $sth->execute();
#    @row = $sth->fetchrow_array;
#    $staticid = $row[0];
#    $db_mac = $row[1];

#    if ("$db_mac" eq "") {
#      print "1\n";
#      # Static ARP entry for the gateway not yet present. Add it.

#      $sql = "INSERT INTO arp_static (mac, ip, sensorid) VALUES ('$mac', '$dhcpserver', $sensorid)";
#      $sth = $dbh->prepare($sql);
#      $er = $sth->execute();

#      $sql = "SELECT id FROM arp_static WHERE mac = '$mac' AND ip = '$dhcpserver' AND sensorid = '$sensorid'";
#      $sth = $dbh->prepare($sql);
#      $er = $sth->execute();
#      @row = $sth->fetchrow_array;
#      $staticid = $row[0];

#      $sql = "INSERT INTO sniff_hosttypes (staticid, type) VALUES ('$staticid', '2')";
#      $sth = $dbh->prepare($sql);
#      $er = $sth->execute();
#    } elsif ("$db_mac" ne "$mac") {
#      print "2\n";
#      # Static ARP entry for the gateway present, but with a different MAC address. Update it.

#      $sql = "UPDATE arp_static SET mac = '$mac' WHERE sensorid = $sensorid AND ip = '$dhcpserver'";
#      $sth = $dbh->prepare($sql);
#      $er = $sth->execute();
#    } else {
#      print "3\n";
#      $sql = "SELECT id FROM sniff_hosttypes WHERE staticid = '$staticid' AND type = '2'";
#      $sth = $dbh->prepare($sql);
#      $er = $sth->execute();
#      @row = $sth->fetchrow_array;
#      $db_id = $row[0];

#      if ("$db_id" eq "") {
#        $sql = "INSERT INTO sniff_hosttypes (staticid, type) VALUES ('$staticid', '2')";
#        $sth = $dbh->prepare($sql);
#        $er = $sth->execute();
#      }
#    }
#  }
#}

##################
# TCPdump part (handles most stuff)
##################

# Setting up the pcap options
my %args = (
        SNAPLEN => 1024,         # Num bytes to capture from packet
        PROMISC => 1,           # Operate in promiscuous mode?
        TIMEOUT => 1000,        # Read timeout (ms)
        NUMPACKETS => -1,       # Pkts to read (-1 = loop forever)
        FILTER => '',           # Filter string
        USERDATA => '',         # Passed as first arg to callback fn
        SAVEFILE => '',         # Default save file
        DEV => "$tap",          # Network interface to open
);

# Putting the interface on promiscuous mode to catch more traffic
`ifconfig $tap promisc up`;

$i = 0;
$e = 0;

# Function to handle the sniffing
sub filter_packets {
  my ($userdata, $header, $pckt) = @_;
  my $eth_obj = NetPacket::Ethernet->decode($pckt);
  $eth_type = $eth_obj->{type};
  $head = 0;

  $ts = time();
  if ($ts > $protos_refresh) {
    #### SNIFF PROTOS ####
    refresh_protos(0);
    refresh_protos(1);
    refresh_protos(11);
    refresh_protos(12);
    refresh_protos(11768);

    $ts = time();
    $protos_refresh = $ts + $c_sniff_protos_refresh;
  }

  if ($ts > $mail_refresh) {
    %arp_mail = ();
    %dhcp_mail = ();

    # Get the info needed for the mailreport stuff [ARP]
    $sql = "SELECT login.email, login.gpg, report_content.sensor_id, report_content.id FROM report_content, login ";
    $sql .= " WHERE login.id = report_content.user_id AND report_content.template = 5 AND report_content.active = TRUE ";
    $sql .= " AND (report_content.sensor_id = $sensorid OR (report_content.sensor_id = -1 AND (login.organisation = $org OR login.organisation = $admin_org)))";
    $sth = $dbh->prepare($sql);
    $er = $sth->execute();

    while (@row = $sth->fetchrow_array) {
      $email = $row[0];
      $gpg = $row[1];
      $db_sid = $row[2];
      $rcid = $row[3];
      if ("$db_sid" eq "-1" || "$db_sid" eq "$sensorid") {
        $arp_mail{"$email"} = "$gpg-$rcid";
      }
    }

    # Get the info needed for the mailreport stuff [DHCP]
    $sql = "SELECT login.email, login.gpg, report_content.sensor_id, report_content.id FROM report_content, login ";
    $sql .= " WHERE login.id = report_content.user_id AND report_content.template = 7 AND report_content.active = TRUE ";
    $sql .= " AND (report_content.sensor_id = $sensorid OR (report_content.sensor_id = -1 AND (login.organisation = $org OR login.organisation = $admin_org)))";
    $sth = $dbh->prepare($sql);
    $er = $sth->execute();

    while (@row = $sth->fetchrow_array) {
      $email = $row[0];
      $gpg = $row[1];
      $db_sid = $row[2];
      $rcid = $row[3];
      if ("$db_sid" eq "-1" || "$db_sid" eq "$sensorid") {
        $dhcp_mail{"$email"} = "$gpg-$rcid";
      }
    }
    $mail_refresh = $ts + $c_mail_refresh;
  }

  # Checking to see if we need to refresh the static dhcp list
  if ($ts > $dhcp_refresh) {
    %dhcp_static = ();
    #### DHCP STATIC ####
    # Filling the local scripts static dhcp server list
    $sql = "SELECT mac, ip FROM arp_static, sniff_hosttypes WHERE arp_static.id = sniff_hosttypes.staticid AND sniff_hosttypes.type = 2 AND arp_static.sensorid = $sensorid";
    $sth = $dbh->prepare($sql);
    $er = $sth->execute();

    while (@row = $sth->fetchrow_array) {
      $db_mac = $row[0];
      $db_ip = $row[1];
      $dhcp_static{"$db_ip"} = $db_mac;
    }
    $ts = time();
    $dhcp_refresh = $ts + $c_dhcp_static_refresh;
  }

  if (! exists $sniff_protos_eth{$eth_type}) {
    $check = add_proto_type($sensorid, $head, $eth_type);
  }

  #########################################
  # (1) IP Protocol
  #########################################

  if ($eth_obj->{type} eq 2048) {
    $head = 1;
    # IP packet
    $ip_obj = NetPacket::IP->decode($eth_obj->{data});
    $proto = $ip_obj->{proto};

    $src_ip = $ip_obj->{src_ip};
    $src_mac = $eth_obj->{src_mac};
    $src_mac = colonmac($src_mac);

    $dst_ip = $ip_obj->{dest_ip};
    $dst_mac = $eth_obj->{dest_mac};
    $dst_mac = colonmac($dst_mac);

    # Adding protocol type to the database if it doesn't exist yet
    if (! exists $sniff_protos_ip{$proto}) {
      $check = add_proto_type($sensorid, $head, $proto);
    }

    if ($proto == 1) {
      $head = 11;
      # ICMP protocol detected
      my $icmp_obj = NetPacket::ICMP->decode($ip_obj->{data});
      $icmp_type = $icmp_obj->{type};
      if (! exists $sniff_protos_icmp{$icmp_type}) {
        $check = add_proto_type($sensorid, $head, $icmp_type);
      }
    } elsif ($proto == 2) {
      $head = 12;
      # IGMP protocol detected
      my $igmp_obj = NetPacket::IGMP->decode($ip_obj->{data});
      $igmp_type = $igmp_obj->{type};
      if (! exists $sniff_protos_igmp{$igmp_type}) {
        $check = add_proto_type($sensorid, $head, $igmp_type);
      }  
    } elsif ($proto == 6) {
      # TCP protocol detected
      my $tcp_obj = NetPacket::TCP->decode($ip_obj->{data});
      $flags = $tcp_obj->{flags};
    } elsif ($proto == 17) {
      # UDP protocol detected
      $udp_obj = NetPacket::UDP->decode($ip_obj->{data});
      $dst_port = $udp_obj->{dest_port};
      
      if ($dst_port == 68) {
        $head = 11768;
        $dhcp_obj = Net::DHCP::Packet->new($udp_obj->{data});
        $op = $dhcp_obj->{op};
        if ($op == 2) {
          $check = add_host_type($src_ip, $sensorid, 2);
        }
        $dhcp_type = $dhcp_obj->getOptionValue(DHO_DHCP_MESSAGE_TYPE());
        if (! exists $sniff_protos_dhcp{$dhcp_type}) {
          $check = add_proto_type($sensorid, $head, $dhcp_type);
        }
        # Don't check for dhcp servers if none is configured in the static list
        $count_dhcp_static = scalar(%dhcp_static);
        if ($count_dhcp_static != 0) {
          if ($op == 2) {
#            $t = $dhcp_obj->toString();
#            print "$t\n";
            $dhcp_ident = $dhcp_obj->getOptionValue(DHO_DHCP_SERVER_IDENTIFIER());
#            print "DHCP[$op]: $src_ip($src_mac) -> $dst_ip($dst_mac)\n";
            $check = chk_dhcp_server($src_mac, $src_ip, $dhcp_ident);
#            print "\n";
          }
        }
      } elsif ($dst_port == 67) {
        $head = 11768;
        $dhcp_obj = Net::DHCP::Packet->new($udp_obj->{data});
        $op = $dhcp_obj->{op};
        $dhcp_type = $dhcp_obj->getOptionValue(DHO_DHCP_MESSAGE_TYPE());
        if ("$dhcp_type" ne "") {
          if (! exists $sniff_protos_dhcp{$dhcp_type}) {
            $check = add_proto_type($sensorid, $head, $dhcp_type);
          }
        }
#        print "DHCP[$op]: $src_ip($src_mac) -> $dst_ip($dst_mac)\n";
      }
    } elsif ($proto == 41) {
      # IPv6 protocol detected
    }
  }
#  elsif ($eth_obj->{type} == ETH_TYPE_SNMP) {
#    print "ETH_TYPE_SNMP\n";
#  }
  elsif ($eth_obj->{type} == 2054) {
    $ts = time();

    if ($ts > $static_refresh) {
      %arp_static = ();

      #### ARP STATIC ####
      # Filling the local scripts static arp list
      $sql = "SELECT mac, ip FROM arp_static WHERE sensorid = $sensorid";
      $sth = $dbh->prepare($sql);
      $er = $sth->execute();

      while (@row = $sth->fetchrow_array) {
        $db_mac = $row[0];
        $db_ip = $row[1];
        $arp_static{"$db_ip"} = $db_mac;
      }
      $static_refresh = $ts + $c_arp_static_refresh;
    }

    if ($ts > $cache_refresh) {
      #### ARP CACHE ####
      $sql = "SELECT COUNT(id) as total FROM arp_cache WHERE sensorid = $sensorid";
      $sth = $dbh->prepare($sql);
      $er = $sth->execute();
      @row = $sth->fetchrow_array;
      $count = $row[0];
      if ($count == 0) {
        %arp_cache = ();
      }
      $cache_refresh = $ts + $c_arp_static_refresh;
    }

    my $arp_obj = NetPacket::ARP->decode($eth_obj->{data});
    $arp_opcode = $arp_obj->{opcode};
#    $eth_data = unpack('H*', $eth_obj->{data});
#    print "ETHDATA: $eth_data\n";
#    $data = unpack('A*', $header);
#    Dumper($data);
#    print "DATA: $data\n";

    if ($arp_opcode == 1) {
      #######################
      # (2.1.1) ARP Query
      #######################
      $arp_source_mac = colonmac($arp_obj->{sha});
      $arp_source_ip = hextoip($arp_obj->{spa});
      $arp_dest_mac = colonmac($arp_obj->{tha});
      $arp_dest_ip = hextoip($arp_obj->{tpa});

#      print "ARPQUERY: $arp_source_mac ($arp_source_ip) -> $arp_dest_mac ($arp_dest_ip)\n";

      $check = add_arp_cache($arp_source_mac, $arp_source_ip, $sensorid);
      $check = chk_static_arp($arp_source_mac, $arp_source_ip, $sensorid);
    } elsif ($arp_opcode == 2) {
      #######################
      # (2.1.1) ARP Reply
      #######################
      $arp_source_mac = colonmac($arp_obj->{sha});
      $arp_source_ip = hextoip($arp_obj->{spa});
      $arp_dest_mac = colonmac($arp_obj->{tha});
      $arp_dest_ip = hextoip($arp_obj->{tpa});

#      print "ARPREPLY: $arp_source_mac ($arp_source_ip) -> $arp_dest_mac ($arp_dest_ip)\n";

      $check = add_arp_cache($arp_dest_mac, $arp_dest_ip, $sensorid);
      $check = chk_static_arp($arp_dest_mac, $arp_dest_ip, $sensorid);

      # Reply source check
      $arp_source_ip_long = ip2long($arp_source_ip);
      if ($arp_source_ip_long > $ifmin && $ifmax > $arp_source_ip_long) {
        $check = add_arp_cache($arp_source_mac, $arp_source_ip, $sensorid);
        $check = chk_static_arp($arp_source_mac, $arp_source_ip, $sensorid);
      }
    }
  }
}

# Call the filter_arp function for packets received with type "ARP"
Net::PcapUtils::loop(\&filter_packets, %args);
