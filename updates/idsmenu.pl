#!/usr/bin/perl -w

#########################################
# IDSmenu script for IDS Sensor
# SURFnet IDS
# Version 1.02.05
# 04-09-2006
# Jan van Lith & Kees Trippelvitz
# Modified by Peter Arts
#########################################

#############################################
# Changelog:
# 1.02.05 Rerelease as perl script
# 1.02.04 Key and certificate check bugfix
# 1.02.03 Initial release
#############################################

use File::Basename;

$basedir = "/cdrom/scripts/";
do "$basedir/perl.conf";
require "$basedir/functions.inc.pl";

$ip_error = 0;

sub idsmenu_showstatus() {
  ### Sensor name ###
  $sensor = getsensor();
  printmsg("Sensor name:", $sensor);
  
  ### Bridge status ###
  $chkbridge = chkbridge();
  if ($chkbridge == 1) {
    $if = getif();
  } else {
    $if = $br;
  }
  
  ### OpenVPN status ###
  $chkopenvpn = chkopenvpn();
  if ($chkbridge != 1 && $chkopenvpn != 1) {
    printmsg("Checking bridge status:", $chkbridge);
    printmsg("Checking OpenVPN status:", $chkopenvpn);
  }
  
  ### Active interface ###
  printmsg("Active interface:", $if);
  if ($if eq "false") {
    $ip_error = 1;
  }
  
  ### IP address active interface ###
  if ($ip_error == 1) {
    # Don't try to get the interface IP if there's no active interface.
    printmsg("Interface IP address:", "ignore");
  } else {
    # Active interface present, get IP.
    $if_ip = getifip($if);
    printmsg("Interface IP address:", $if_ip);
    if ($if_ip eq "false") {
      $ip_error = 1;
    }
  }
  
  ### Checking DNS resolving ###
  if ($ip_error == 1) {
    printmsg("Checking name resolving:", "ignore");
  } else {
    $chkresolv = getresolv($server);
    if ($chkresolv eq "false") {
      $ip_error = 1;
    } else {
      $chkresolv = 0;
    }
    printmsg("Checking name resolving:", $chkresolv);
  }
  
  ### Network configuration method ###
  $netconf = getnetconf();
  printmsg("Network configuration method:", $netconf);
  
  ### OpenVPN port status ###
  if ($ip_error == 1) {
    printmsg("Checking OpenVPN port:", "ignore");
  } else {
    $chkopenvpn = getportstatus($if, 1194);
    printmsg("Checking OpenVPN port:", $chkopenvpn);
  }
  
  ### Update port status ###
  if ($ip_error == 1) {
    printmsg("Checking updates port:", "ignore");
  } else {
    $chkupdates = getportstatus($if, 4443);
    printmsg("Checking updates port:", $chkupdates);
  }

  ### ca.crt check ###
  $chkca = chkca();
  printmsg("Checking ca.crt:", $chkca);
  
  ### sensor.crt check ###
  $chkcert = chksensorcert();
  printmsg("Checking sensor certificate:", $chkcert);

  ### sensor.key check ###
  $chkkey = chksensorkey();
  printmsg("Checking sensor key:", $chkkey);

  ### Read/write check ###
  $chkrw = chkrw();
  printmsg("Checking read/write status", $chkrw);
  
  ### Wget authentication check ###
  if ($ip_error == 1) {
    printmsg("Checking wget authentication:", "ignore");
  } else {
    $wgetv = getwgetversion();
    $wgetarg = "";
    if ($wgetv ne "1.9.1") {
      $wgetarg = "--no-check-certificate";
    }
    $chkwgetauth = chkwgetauth($wgetarg);
    printmsg("Checking wget authentication:", $chkwgetauth);
  }

  ### Checking client.conf ###
  $chkclient = chkclientconf();
  printmsg("Checking client.conf:", $chkclient);
  
  ### Checking network config ###
  print "${y}Checking network config...${n}\n";
  if ($ip_error != 1) {
    ### Checking gateway ###
    $if_gateway = getnetinfo("interface", "Gateway", $if);
    printmsg("Gateway:", $if_gateway);
    if ($if_gateway !~ /^(1|2|3)$/) {
      $chkgw = chkreach($if_gateway);
      printmsg("Pinging gateway:", $chkgw);
    }
    $if_netmask = getnetinfo("interface", "Netmask", $if);
    printmsg("Netmask:", $if_netmask);
    $if_broadcast = getnetinfo("interface", "Broadcast", $if);
    printmsg("Broadcast:", $if_broadcast);
  }
  
  ### Checking DNS domain ###
  $if_domain = getnetinfo("interface", "Domain", $if);
  printmsg("Domain:", $if_domain);
  
  ### Checking DNS nameserver ###
  $if_name = getnetinfo("interface", "Nameserver", $if);
  printmsg("Nameserver:", $if_name);
  if ($if_name !~ /^(1|2|3)$/) {
    $chkname = chkreach($if_name);
    printmsg("Pinging nameserver:", $chkname);
  }
  
  &prompt("\nPress enter to continue...");
}

sub idsmenu_startsensor() {
  system("$basedir/startclient.pl");
  &prompt("Press enter to continue...");
}

sub idsmenu_stopsensor() {
  system("$basedir/stopclient.pl");
  &prompt("Press enter to continue...");
}

sub idsmenu_login() {
  system("/usr/bin/clear");
  system("/sbin/getty 38400 tty1");
}

sub idsmenu_reboot() {
  system("/usr/bin/clear");
  system("/sbin/init 6");
}

sub idsmenu_shutdown() {
  system("/usr/bin/clear");
  system("/sbin/init 0");
}

$input = "";
while (1==1) {
  system("/usr/bin/clear");
  print "SURFnet IDS menu:\n";
  print "\t1. Status info\n";
  print "\t2. Start Sensor\n";
  print "\t3. Stop Sensor\n";
  print "\t4. Update\n";
  print "\t5. Login\n";
  print "\t6. Configure network\n";
  print "\t7. Enable/Disable SSH\n";
  print "\t8. Reboot\n";
  print "\t9. Shutdown\n";
  $input = &prompt("\tPlease select one of the above (1-2): ");
  chomp($input);
  system("/usr/bin/clear");
  if ("$input" eq 1) {
    idsmenu_showstatus();
  } elsif ($input eq 2) {
    idsmenu_startsensor();
  } elsif ($input eq 3) {
    idsmenu_stopsensor();
  } elsif ($input eq 4) {
    idsmenu_update();
  } elsif ($input eq 5) {
    idsmenu_login();
  } elsif ($input eq 6) {
    idsmenu_netconfig();
  } elsif ($input eq 7) {
    idsmenu_ssh();
  } elsif ($input eq 8) {
    idsmenu_reboot();
  } elsif ($input eq 9) {
    idsmenu_shutdown();
  } else {
    print "${r}Invalid input. Try again!${n}\n";
  }
}
