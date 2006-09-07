#!/usr/bin/perl -w

###############################################
# Network setup script for SURFnet IDS sensor #
# SURFnet IDS                                 #
# Version 1.02.03                             #
# 04-09-2006                                  #
# Peter Arts & Kees Trippelvitz               #
###############################################

#########################################################################################
# Copyright (C) 2005 SURFnet                                                            #
# Authors Peter Arts & Kees Trippelvitz                                                 #
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
#########################################################################################

#############################################
# Changelog:
# 1.02.03 Rerelease as perl script
# 1.02.02 Initial release
#############################################

################
# Variables    #
################
$basedir = "/cdrom/scripts";
do "$basedir/perl.conf";
require "$basedir/functions.inc.pl";

################
# Start script #
################
# Setting some empty variables.
$ipsensor = "";
$iphoney = "";
$netmask = "";
$gateway = "";
$domain = "";
$broad = "";
$primary = "";

# Set a static IP address
sub set_static_ip() {
  system("$basedir/stopclient.pl");
  $done = 1;
  while ($done != 0) {
    #####################
    system("/usr/bin/clear");
    print "Please enter the IP configuration for this network.\n";
    print "Each item should be entered as an IP address in dotted-decimal notation.\n";
    print " (for example, 1.2.3.4).\n\n";

    ### Reading sensor IP address
    $valid_ip = 1;
    $default = "";
    while ($valid_ip != 0) {
      if (-r $networkconf) {
        $default = `cat $networkconf | grep "IP_sensor: " | awk '{print \$2}'`;
      }
      chomp($default);
      $sensorip = &prompt("IP address sensor [$default]: ", $default);
      $valid_ip = validip($sensorip);
      printmsg("Checking input:", $valid_ip);
    }
    
    ### Reading netmask
    $valid_ip = 1;
    $default = "";
    while ($valid_ip != 0) {
      if (-r "$networkconf") {
        $default = `cat $networkconf | grep "Netmask: " | awk '{print \$2}'`;
      }
      chomp($default);
      $netmask = &prompt("Netmask [$default]: ", $default);
      $valid_ip = validip($netmask);
    }
    
    ### Reading gateway
    $valid_ip = 1;
    $default = "";
    while ($valid_ip != 0) {
      if (-r $networkconf) {
        $default = `cat $networkconf | grep "Gateway: " | awk '{print \$2}'`;
      }
      chomp($default);
      $gw = &prompt("Default gateway [$default]: ", $default);
      $valid_ip = validip($gw);
    }

    ### Reading broadcast address
    $valid_ip = 1;
    $default = "";
    while ($valid_ip != 0) {
      if (-r $networkconf) {
        $default = `cat $networkconf | grep "Broadcast: " | awk '{print \$2}'`;
      }
      chomp($default);
      $bc = &prompt("Broadcast address [$default]: ", $default);
      $valid_ip = validip($bc);
    }

    ### Reading primary nameserver
    $valid_ip = 1;
    $default = "";
    while ($valid_ip != 0) {
      if (-r $networkconf) {
        $default = `cat $networkconf | grep "Nameserver: " | awk '{print \$2}'`;
      }
      chomp($default);
      $ns = &prompt("Primary nameserver [$default]: ", $default);
      $valid_ip = validip($ns);
    }
    
    ### Reading domain
    $valid_ip = 1;
    $default = "";
    while ($valid_ip != 0) {
      if (-r $networkconf) {
        $default = `cat $networkconf | grep "Domain: " | awk '{print \$2}'`;
      }
      chomp($default);
      $domain = &prompt("Domain (no IP) [$default]: ", $default);
      chomp($domain);
      if ($domain eq "") {
        $valid_ip = 1;
      } else {
        $valid_ip = 0;
      }
    }

    # Set configuration in network_if.conf:
    open(NCONF, "> $networkconf");
    print NCONF "# network.conf -- configuration file for the network interface\n";
    print NCONF "Method: static\n";
    print NCONF "IP_sensor: $sensorip\n";
    print NCONF "Netmask: $netmask\n";
    print NCONF "Gateway: $gw\n";
    print NCONF "Broadcast: $bc\n";
    print NCONF "Domain: $domain\n";
    print NCONF "Nameserver: $ns\n";
    close(NCONF);

    system("/usr/bin/clear");
    printmsg("Method:", "static");
    printmsg("IP_sensor:", $sensorip);
    printmsg("Netmask:", $netmask);
    printmsg("Gateway:", $gw);
    printmsg("Broadcast:", $bc);
    printmsg("Domain:", $domain);
    printmsg("Nameserver:", $ns);
    ###############

    $check = 1;
    while ($check != 0) {
      $input = &prompt("Is this information correct [Y/n] ?: ");
      if ($input =~ /^(Y|y|N|n)$/) {
        $check = 0;
      }
    }
    if ($input =~ /^(Y|y)$/) {
      $checkstart = `ps -ef | grep startclient | grep -v grep | wc -l`;
      chomp($checkstart);
      if ($checkstart == 0) {
        # Stop client
	system("$basedir/stopclient.pl");
	print "${y}Stopping/starting client.${n}\n";
	system("$basedir/startclient.pl");
	$done = 0;
      }
    }
  }
}

# Set dynamic IP
sub set_dynamic_ip() {
  $chksensor = chksensorstatus();
  if ($chksensor == 0) {
    # Stop client first
    system("$basedir/stopclient.pl");
  }

  # Set DHCP networking in network_if.conf:
  $checkconf = `cat $networkconf | grep -i Method | wc -l`;
  if ($checkconf != 0) {
    $tempfile = `mktemp -p $basedir`;
    `sed 's/^Method:.*\$/Method: dhcp/' $networkconf > $tempfile`;
    `mv $tempfile $networkconf`;
  } else {
    open(NCONF, "> $networkconf");
    print NCONF "# network.conf -- configuration file for the network interface\n";
    print NCONF "Method: dhcp\n";
    close(NCONF);
  }

  $checkstart = `ps -ef | grep startclient | grep -v grep | wc -l`;
  if ($checkstart == 0) {
    # Start client
    system("$basedir/startclient.pl");
  }
}

# Show menu
while (1) {
  system("/usr/bin/clear");
  print "Do you want to use static IP configuration or DHCP?\n";
  print "\t\tS. Use static IP\n";
  print "\t\tD. Use DHCP\n";
  $checkstart = `ps -ef | grep startclient | grep -v grep | wc -l`;
  if ($checkstart != 0) {
    print "\n";
    $choice = &prompt("Please select one of the above (S/D): ");
    if ($choice =~ /^(S|s)$/) {
      set_static_ip();
      exit;
    } elsif ($choice =~ /^(D|d)$/) {
      set_dynamic_ip();
      exit;
    } else {
      print "Unknown option!\n";
    }
  } else {
    print "\t\tC. Cancel\n\n";
    $choice = &prompt("Please select one of the above (S/D/C): ");
    if ($choice =~ /^(S|s)$/) {
      set_static_ip();
      exit;
    } elsif ($choice =~ /^(D|d)$/) {
      set_dynamic_ip();
      exit;
    } elsif ($choice =~ /^(C|c)$/) {
      exit;
    } else {
      print "Unknown option!\n";
    }
  }
}
