#!/usr/bin/perl

####################################
# ARP detection module             #
# SURFids 3.00                     #
# Changeset 004                    #
# 25-07-2008                       #
# Jan van Lith & Kees Trippelvitz  #
####################################

#####################
# Changelog:
# 004 Ignoring IEEE802.3 Length Fields for ethernet packets
# 003 Changed sensorid retrieval
# 002 Added blacklists
# 001 Ignore checking the gateway if it is not in the local network range
#####################

##################
# Modules used
##################
require Net::Pcap;
use Net::PcapUtils;
use Net::DHCP::Packet;
use Net::DHCP::Constants;
use NetPacket::IP;
use NetPacket::IPv6;
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
use Data::Dumper;
#use NetPacket::Ethernet qw(:types);
#use NetPacket::Ethernet qw(:strip);
#use NetPacket::IP qw(:strip);

##################
# Variables used
##################
do '/etc/surfnetids/surfnetids-tn.conf';
require "$c_surfidsdir/scripts/tnfunctions.inc.pl";
our $tap = $ARGV[0];
$sensorid = $ARGV[1];
our $source = 'detectarp.pl';

#################
# Blacklists
#################
$arp_blacklist{"01:00:0c:cd:cd:cd"} = 1;
$arp_blacklist{"01:00:0C:CD:CD:CD"} = 1;

# Used by ActiveSync, hence classified as a false positive
$dhcp_blacklist{"169.254.2.1"} = 1;

##################
# Data sets
##################
#require "$c_surfidsdir/scripts/types_data.pl";

##################
# Main script
##################

$ts = time();

# Connect to the database (dbh = DatabaseHandler or linkserver)
$dbconn = dbconnect();

if ("$sensorid" eq "") {
  logsys($f_log_error, "SCRIPT_FAIL", "Missing sensor ID.");
  exit 1;
}
if ("$tap" eq "") {
  logsys($f_log_error, "SCRIPT_FAIL", "Missing tap interface.");
  exit 1;
}

# Check for existance of the tap interface
`ifconfig $tap 2>/dev/null`;
if ($? != 0) {
  logsys($f_log_error, "SCRIPT_FAIL", "Could not find interface ($tap).");
  exit 1;
}

# Getting the sensor ID
if ("$dbconn" ne "false") {
  $sql = "SELECT organisation, networkconfig, vlanid, sensors.keyname, arp, dhcp, ipv6, protos FROM sensors ";
  $sql .= " LEFT JOIN sensor_details ON sensors.keyname = sensor_details.keyname ";
  $sql .= " WHERE sensors.id = '$sensorid' ";
  $sth = $dbh->prepare($sql);
  $er = $sth->execute();

  $count = $sth->rows;
  if ($count == 0) {
    logsys($f_log_error, "SCRIPT_FAIL", "Could not find a sensor record.");
    exit 1;
  }

  @row = $sth->fetchrow_array;
  $org = $row[0];
  $netconf = $row[1];
  our $g_vlanid = $row[2];
  our $sensor = $row[3];
  $db_arp = $row[4];
  $db_dhcp = $row[5];
  $db_ipv6 = $row[6];
  $db_protos = $row[7];

  $ts = time();
  $toggle_refresh = $ts + $c_sniff_toggle_refresh;

  $db_arp == 1 ? print "ARP enabled\n" : print "ARP disabled\n";
  $db_dhcp == 1 ? print "DHCP enabled\n" : print "DHCP disabled\n";
  $db_ipv6 == 1 ? print "IPv6 enabled\n" : print "IPv6 disabled\n";
  $db_protos == 1 ? print "Protos enabled\n" : print "Protos disabled\n";

  if ("$org" eq "") {
    logsys($f_log_error, "SCRIPT_FAIL", "Missing organisation ID.");
    exit 1;
  }
} else {
  logsys($f_log_error, "DB_FAIL", "Missing database connection.");
  exit 1;
}

# Getting admin organisation ID
$sql = "SELECT id FROM organisations WHERE organisation = 'ADMIN'";
$sth = $dbh->prepare($sql);
$er = $sth->execute();

@row = $sth->fetchrow_array;
$admin_org = $row[0];

if ($db_arp == 1) {
#  print "[ARP] refresh_mail\n";
  %arp_mail = ();
  refresh_mail("arp", $org, $admin_org, $sensorid);
}

if ($db_dhcp == 1) {
#  print "[DHCP] refresh_mail\n";
  %dhcp_mail = ();
  refresh_mail("dhcp", $org, $admin_org, $sensorid);
}

if ($db_ipv6 == 1) {
#  print "[IPv6] refresh_mail\n";
  %ipv6_mail = ();
  refresh_mail("ipv6", $org, $admin_org, $sensorid);
}

$mail_refresh = $ts + $c_mail_refresh;

# Initialize the scripts arp cache, alert and static hashes
%arp_alert = ();
%dhcp_alert = ();
%ipv6_alert = ();
%sniff_protos_eth = ();
%sniff_protos_ip = ();
%sniff_protos_ipv6 = ();
%sniff_protos_icmp = ();
%sniff_protos_igmp = ();
%sniff_protos_dhcp = ();

if ($db_arp == 1) {
#  print "[ARP] refresh_cache\n";
  %arp_cache = ();
  refresh_cache();
  $ts = time();
  $cache_refresh = $ts + $c_arp_cache_refresh;

#  print "[ARP] refresh_static\n";
  %arp_static = ();
  refresh_static("arp");
  $ts = time();
  $static_refresh = $ts + $c_arp_static_refresh;
}

if ($db_dhcp == 1) {
#  print "[DHCP] refresh_static\n";
  %dhcp_static = ();
  refresh_static("dhcp");
  $ts = time();
  $dhcp_refresh = $ts + $c_dhcp_static_refresh;
}

if ($db_ipv6 == 1) {
#  print "[IPv6] refresh_static\n";
  %ipv6_static = ();
  refresh_static("ipv6");
  $ts = time();
  $ipv6_refresh = $ts + $c_ipv6_static_refresh;
}

#### SNIFF PROTOS ####
if ($db_protos == 1) {
    refresh_protos(0);
    refresh_protos(1);
    refresh_protos(11);
    refresh_protos(12);
    refresh_protos(11768);
    refresh_protos(34525);

    $ts = time();
    $protos_refresh = $ts + $c_sniff_protos_refresh;
}

##################
# Getting interface info
##################
$ifip = getifip($tap);
$ifmask = getifmask($tap);
$ifmin = ip2long(network($ifip, $ifmask));
$ifmax = ip2long(bc($ifip, $ifmask));
if ("$netconf" eq "dhcp") {
  $gw = `cat /var/lib/dhcp3/$tap.leases | grep routers | tail -n1 | awk '{print \$3}' | awk -F\\; '{print \$1}'`;
  chomp($gw);
  if ("$gw" eq "") {
    $gw = gw($ifip, $ifmask);
  }
} else {
  @netconf_ar = split(/\|/, $netconf);
  $gw = $netconf_ar[1];
}
if ("$gw" eq "") {
  $gw = gw($ifip, $ifmask);
}

logsys($f_log_debug, "NOTIFY", "Detected gateway: $gw");

#print "GW: $gw\n";

##################
# Checking the gateway IP/MAC pair.
##################

if ($db_arp == 1) {
  $sql = "SELECT mac FROM arp_static WHERE sensorid = $sensorid AND ip = '$gw'";
  $sth = $dbh->prepare($sql);
  $er = $sth->execute();
  @row = $sth->fetchrow_array;
  $db_mac = $row[0];

  if ($c_arping_package eq "arping") {
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
    }
  } elsif ($c_arping_package eq "iputils-arping") {
    `arping -V 2>/dev/null`;
    $arpec = $?;
    $gwlong = ip2long($gw);
    if ($gwlong < $ifmin && $gwlong > $ifmax) {
      $arpec == 1;
    }
    if ($arpec == 0) {
      %maclist = ();
      open(ARPING, "arping -I $tap -c 4 $gw | awk '{print \$5}' | ");
      while (<ARPING>) {
        $mac = $_;
        chomp($mac);
        $mac =~ s/\[//g;
        $mac =~ s/\]//g;
        if ($mac =~ /([[:xdigit:]][[:xdigit:]]:){5}[[:xdigit:]][[:xdigit:]]/) {
            $maclist{"$mac"} = 0;
        }
      }
      close(ARPING);
    }
  } else {
    print "Invalid arping package configured, check config (c_arping_package)\n";
    $arpec = 1;
  }
  if ($arpec == 0) {
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
}

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

  $head = 0;
  $eth_type = $eth_obj->{type};
  $dst_mac = $eth_obj->{dest_mac};
  $dst_mac = colonmac($dst_mac);
  $src_mac = $eth_obj->{src_mac};
  $src_mac = colonmac($src_mac);

  $ts = time();
  if ($ts > $toggle_refresh) {
    # Update module toggles
    $sql = "SELECT arp, dhcp, ipv6, protos FROM sensors WHERE sensors.id = '$sensorid'";
    $sth = $dbh->prepare($sql);
    $er = $sth->execute();

    $count = $sth->rows;
    if ($count > 0) {
      @row = $sth->fetchrow_array;
      $db_arp = $row[0];
      $db_dhcp = $row[1];
      $db_ipv6 = $row[2];
      $db_protos = $row[3];
    }

    $ts = time();
    $toggle_refresh = $ts + $c_sniff_toggle_refresh;
  }

  if ($db_protos == 1) {
    $ts = time();
    if ($ts > $protos_refresh) {
      #### SNIFF PROTOS ####
      refresh_protos(0);
      refresh_protos(1);
      refresh_protos(11);
      refresh_protos(12);
      refresh_protos(11768);
      refresh_protos(34525);

      $ts = time();
      $protos_refresh = $ts + $c_sniff_protos_refresh;
    }
  }

  if ($ts > $mail_refresh) {
    if ($db_arp == 1) {
#      print "[ARP] refresh arp_mail\n";
      refresh_mail("arp", $org, $admin_org, $sensorid);
    }

    if ($db_dhcp == 1) {
#      print "[DHCP] refresh dhcp_mail\n";
      refresh_mail("dhcp", $org, $admin_org, $sensorid);
    }

    if ($db_ipv6 == 1) {
#      print "[IPv6] refresh ipv6_mail\n";
      refresh_mail("ipv6", $org, $admin_org, $sensorid);
    }
    $ts = time();
    $mail_refresh = $ts + $c_mail_refresh;
  }

  if ($db_dhcp == 1) {
    # Checking to see if we need to refresh the static dhcp list
    if ($ts > $dhcp_refresh) {
#      print "[DHCP] refresh dhcp_static\n";
      %dhcp_static = ();
      refresh_static("dhcp");
      $ts = time();
      $dhcp_refresh = $ts + $c_dhcp_static_refresh;
    }
  }

  if ($db_protos == 1) {
    # Check ethernet protocol
    if ($eth_type > 1500) {
      if (! exists $sniff_protos_eth{$eth_type}) {
        $check = add_proto_type($sensorid, $head, $eth_type);
      }
    } else {
      if ("$dst_mac" eq "01:80:c2:00:00:00") {
        # Adding STP as type -1
        # Reason: IEEE 802.3 ethernet packets have no type field, thus no type
        # $eth_obj->{type} returns the length field for IEEE 802.3 packets.
        $check = add_proto_type($sensorid, $head, "-1");
      }
    }
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
    $dst_ip = $ip_obj->{dest_ip};

    if ($db_protos == 1) {
      # Adding protocol type to the database if it doesn't exist yet
      if (! exists $sniff_protos_ip{$proto}) {
        $check = add_proto_type($sensorid, $head, $proto);
      }
    }

    if ($proto == 1) {
      $head = 11;
      # ICMP protocol detected
      my $icmp_obj = NetPacket::ICMP->decode($ip_obj->{data});
      $icmp_type = $icmp_obj->{type};
      $icmp_code = $icmp_obj->{code};
      if ($db_protos == 1) {
        if (! exists $sniff_protos_icmp{"$icmp_type-$icmp_code"}) {
          $check = add_proto_type($sensorid, $head, $icmp_type, $icmp_code);
        }
      }
    } elsif ($proto == 2) {
      $head = 12;
      # IGMP protocol detected
      my $igmp_obj = NetPacket::IGMP->decode($ip_obj->{data});
      $igmp_t = $igmp_obj->{type};
      $igmp_v = $igmp_obj->{version};
      $igmp_type = $igmp_v . $igmp_t;

      if ($db_protos == 1) {
        if (! exists $sniff_protos_igmp{"$igmp_type"}) {
          $check = add_proto_type($sensorid, $head, $igmp_type);
        }
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
        # DHCP Reply
        $head = 11768;
        $dhcp_obj = Net::DHCP::Packet->new($udp_obj->{data});
        $op = $dhcp_obj->{op};
        $dhcp_type = $dhcp_obj->getOptionValue(DHO_DHCP_MESSAGE_TYPE());
        if ($db_protos == 1) {
          if (! exists $sniff_protos_dhcp{$dhcp_type}) {
            $check = add_proto_type($sensorid, $head, $dhcp_type);
          }
        }

        if ($db_dhcp == 1) {
#          print "[DHCP] dhcp check on port 68\n";
          if ($op == 2) {
            $check = add_host_type($src_ip, $sensorid, 2);
          }
          # Don't check for dhcp servers if none is configured in the static list
          $count_dhcp_static = scalar(%dhcp_static);
          if ($count_dhcp_static != 0) {
            if ($op == 2) {
              $dhcp_ident = $dhcp_obj->getOptionValue(DHO_DHCP_SERVER_IDENTIFIER());
              if (! exists $dhcp_blacklist{"$src_ip"}) {
                $check = chk_dhcp_server($src_mac, $src_ip, $dhcp_ident);
              }
            }
          }
        }
      } elsif ($dst_port == 67) {
        # DHCP Request
        $head = 11768;
        $dhcp_obj = Net::DHCP::Packet->new($udp_obj->{data});
        $op = $dhcp_obj->{op};
        $dhcp_type = $dhcp_obj->getOptionValue(DHO_DHCP_MESSAGE_TYPE());
        if ($db_protos == 1) {
          if ("$dhcp_type" ne "") {
            if (! exists $sniff_protos_dhcp{$dhcp_type}) {
              $check = add_proto_type($sensorid, $head, $dhcp_type);
            }
          }
        }

        if ($db_dhcp == 1) {
#          print "[DHCP] dhcp check on port 67\n";
          $count_dhcp_static = scalar(%dhcp_static);
          if ($count_dhcp_static != 0) {
            if ($dst_ip ne "255.255.255.255") {
              $dhcp_ident = $dhcp_obj->getOptionValue(DHO_DHCP_SERVER_IDENTIFIER());
              if (! exists $dhcp_blacklist{"$dst_ip"}) {
                $check = chk_dhcp_server($dst_mac, $dst_ip, $dhcp_ident);
              }
            }
          }
        }
      }
    } elsif ($proto == 41) {
      # IPv6 protocol detected
      #print "IPv6 detected\n";
    }
  }

  #########################################
  # (2) IPv6 Protocol
  #########################################

  elsif ($eth_type == 34525) {
    $head = 34525;
    # IPv6 packet

    my $ipv6 = NetPacket::IPv6->decode($eth_obj->{data});
    $src_ip6 = $ipv6->{src_ip};
    $src_ip6 = normalize_ipv6($src_ip6);
    $dst_ip6 = $ipv6->{dest_ip};
    $ipv6_data = $ipv6->{data};
    $ipv6_nxt = $ipv6->{nxt};
#    print "IPV6 DATA: $ipv6_data\n";
#    print "IPV6 NXT: $ipv6_nxt\n";
    if ($db_protos == 1) {
      if ("$ipv6_nxt" ne "" && "$ipv6_nxt" ne "0") {
        if (! exists $sniff_protos_ipv6{$ipv6_nxt}) {
          $check = add_proto_type($sensorid, $head, $ipv6_nxt);
        }
      }
    }
    if ($db_ipv6 == 1) {
      if ($ts > $ipv6_refresh) {
#        print "[IPv6] refresh_static\n";
        %ipv6_static = ();
        refresh_static("ipv6");
        $ts = time();
        $ipv6_refresh = $ts + $c_ipv6_static_refresh;
      }

      if ($ipv6_nxt == 58) {
        # IPv6 ICMP
        $unpacked = unpack('H*', $ipv6_data);
#        print "IPV6 ICMP UNPACKED: $unpacked\n";
        ($type, $code, $csum, $chlimit, $flags, $rlife, $reach, $retrans, $options) = parse_icmp6_advertisement($unpacked);
        if ($type eq "86") {
#            print "OPTIONS: $options \n";
#            print "Detected router advertisement\n";
#            print "SRC: $src_mac -> DST: $dst_mac \n";
#            print "SRC: $src_ip6 -> DST: $dst_ip6 \n";
            if ($src_ip6 !~ /^fe80.*/) {		# Ignore link local addresses
                if (! exists $ipv6_static{"$src_ip6"}) {
                    # This source IP is not allowed to send out router advertisements
                    if (!exists $ipv6_alert{"$sensorid-$sourceip"}) {
                        $expiry = 0;
                    } else {
                        $expiry = $ipv6_alert{"$sensorid-$sourceip"};
                    }
                    $cs = time();
#                    print "CS: $cs - EXPIRY: $expiry \n";
                    if ($cs > $expiry) {
                        $aid = add_ipv6_alert($sensorid, $src_ip6);
#                        print "AID 2: $aid \n";
                        if ("$aid" ne "-1") {
                            while ("$options" ne "") {
                                $options = parse_icmp6_options($options, $sensorid, $aid);
#                               print "OPTIONS: $options \n";
                            }
                            $cs = time();
                            $ipv6_alert{"$sensorid-$sourceip"} = $cs + $c_ipv6_alert_expiry;
                        }
                    }
                }
            }
        }
      } # if $ipv6_nxt == 58
    } # if db_ipv6 == 1
  }
#  elsif ($eth_obj->{type} == ETH_TYPE_SNMP) {
#    print "ETH_TYPE_SNMP\n";
#  }

  #########################################
  # (3) ARP
  #########################################

  elsif ($eth_obj->{type} == 2054) {
    if ($db_arp == 1) {
#      print "[ARP] arp check\n";
      if ($ts > $static_refresh) {
        %arp_static = ();
        refresh_static("arp");
        $ts = time();
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

      if ($arp_opcode == 1) {
        #######################
        # (2.1.1) ARP Query
        #######################
        $arp_source_mac = colonmac($arp_obj->{sha});
        $arp_source_ip = hextoip($arp_obj->{spa});
        $arp_dest_mac = colonmac($arp_obj->{tha});
        $arp_dest_ip = hextoip($arp_obj->{tpa});

        if (! exists $arp_blacklist{"$arp_source_mac"}) {
          $check = add_arp_cache($arp_source_mac, $arp_source_ip, $sensorid);
          $check = chk_static_arp($arp_source_mac, $arp_source_ip, $sensorid);
        }
      } elsif ($arp_opcode == 2) {
        #######################
        # (2.1.1) ARP Reply
        #######################
        $arp_source_mac = colonmac($arp_obj->{sha});
        $arp_source_ip = hextoip($arp_obj->{spa});
        $arp_dest_mac = colonmac($arp_obj->{tha});
        $arp_dest_ip = hextoip($arp_obj->{tpa});

        if (! exists $arp_blacklist{"$arp_source_mac"}) {
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
  }
}

# Call the filter_arp function for packets received with type "ARP"
Net::PcapUtils::loop(\&filter_packets, %args);
