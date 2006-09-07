#!/usr/bin/perl

#########################################
# Bridging script for IDS sensor	#
# SURFnet IDS		                #
# Version 1.02.05                       #
# 04-09-2006		                #
# Jan van Lith & Kees Trippelvitz	#
# Modified by Peter Arts                #
#########################################

#########################################################################################
# Copyright (C) 2005 SURFnet                                                            #
# Authors Jan van Lith & Kees Trippelvitz                                               #
# Modified by Peter Arts                                                                #
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

# This script is started by OpenVPN when the tunnel comes up.

#####################
# Changelog:
# 1.02.05 Rereleased script in perl
# 1.02.04 Disabled STP for the bridge and fixed pump bug
# 1.02.03 Changed pump to run on the bridge instead of the eth interface
# 1.02.02 Initial release
#####################

################
# Variables    #
################
$basedir = "/cdrom/scripts";
do "$basedir/perl.conf";
require "$basedir/functions.inc.pl";

################
# Start script #
################

# Check which interface is active
$if = getif();
#printmsg("Checking active interface:", $if);

$if_ip = getifip($if);
#printmsg("Checking IP address:", $if_ip);

# Check if the bridge is up or not.
$chkbridge = chkbridge();

if ($chkbridge == 0) {
  exit;
} else {
  # Check for static of dynamic network connection
  $netconf = getnetconf();
  #printmsg("Network configuration method:", $netconf);

  # Get the interface info.
  if ($netconf eq "dhcp") {
    $if_mask = getnetinfo("interface", "Netmask", $if);
    #printmsg("Checking Netmask:", $if_mask);

    $if_bc = getnetinfo("interface", "Broadcast", $if);
    #printmsg("Checking Broadcast:", $if_bc);

    $if_gw = getnetinfo("interface", "Gateway", $if);
    #printmsg("Checking Gateway:", $if_gw);
  } else {
    $if_ip = getnetinfo("config", "IP_sensor");
    #printmsg("Checking IP address:", $if_ip);

    $if_mask = getnetinfo("config", "Netmask");
    #printmsg("Checking Netmask:", $if_mask);

    $if_bc = getnetinfo("config", "Broadcast");
    #printmsg("Checking Broadcast:", $if_bc);

    $if_gw = getnetinfo("config", "Gateway");
    #printmsg("Checking Gateway:", $if_gw);
  }

  # Setup bridge.
  `brctl addbr $br`;
  #printmsg("Creating bridge device:", $?);
  `brctl addif $br $if`;
  #printmsg("Adding $if to $br:", $?);
  `brctl addif $br $tap`;
  #printmsg("Adding $tap to $br:", $?);
  `brctl stp $br off`;
  #printmsg("Disabling STP on $br:", $?);

  # Starting pump for the bridge interface
  $chkpump = `ps -ef | grep -i pump | grep -v grep | wc -l`;
  if ($chkpump > 0) {
    `killall pump`;
    #printmsg("Killing all dhcp clients:", $?);
  }
  `pump -i $br 2>/dev/null`;
  #printmsg("Starting dhcp client for $br:", $?);

  # Setup interfaces.
  if ($enable_promisc == 1) {
    `ifconfig $if 0.0.0.0 promisc up`;
    #printmsg("Starting interface $if promisc:", $?);
    `ifconfig $tap 0.0.0.0 promisc up`;
    #printmsg("Starting interface $tap promisc:", $?);
  } else {
    `ifconfig $if 0.0.0.0 -promisc up`;
    #printmsg("Starting interface $if:", $?);
    `ifconfig $tap 0.0.0.0 -promisc up`;
    #printmsg("Starting interface $tap:", $?);
  }
  `ifconfig $br $if_ip netmask $if_mask broadcast $if_bc`;
  #printmsg("Configuring bridge interface:", $?);
  `route add -net default gw $if_gw`;
  #printmsg("Adding default gateway:", $?);
}
