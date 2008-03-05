#!/usr/bin/perl

###################################
# Tunnel uninstallation script    #
# SURFnet IDS                     #
# Version 2.00.02                 #
# 07-11-2007                      #
# Jan van Lith & Kees Trippelvitz #
###################################

#####################
# Changelog:
# 2.00.02 Added prompt for ssl dir
# 2.00.01 initial release
#####################

# Color codes
$n = "\033[0;39m";
$y = "\033[1;33m";
$r = "\033[1;31m";
$g = "\033[1;32m";

$targetdir = "/opt/surfnetids";
$configdir = "/etc/surfnetids";
$ssldir = "/etc/apache2/surfidsssl";
$rundir = $0;
$rundir =~ s/uninstall.pl//g;
$logfile = "${rundir}uninstall.log";

##########################
# Includes
##########################

require "../functions_tn.pl";

if (! $ARGV[0]) {
  print "-----------------------------------------------------------------------------------------------\n";
  print "This script will remove anything currently present in the tunnel server SURFids directories!\n";
  print "If you want to keep certain files for later use, make a backup of them and restart this script.\n";
  print "-----------------------------------------------------------------------------------------------\n";

  $confirm = "a";
  while ($confirm !~ /^(n|N|y|Y)$/) {
    $confirm = &prompt("Do you really want to uninstall the SURFids tunnel server installation? [y/n]: ");
  }
} else {
  $confirm = "y";
}
if ($confirm =~ /^(n|N)$/) {
  exit 1;
}

if (! $ARGV[0]) {
  print "-----------------------------------------------------------------------------------------------\n";
  print "This script can clean up the crontab, but it will remove all SURFids related entries!\n";
  print "This includes all SURFids logserver crontab entries!\n";
  print "If you choose not to let the uninstaller remove the entries, you will have to manually modify\n";
  print "the crontab later (/etc/crontab)\n";
  print "-----------------------------------------------------------------------------------------------\n";

  $confirm = "a";
  while ($confirm !~ /^(n|N|y|Y)$/) {
    $confirm = &prompt("Do you want to clear all SURFids crontab entries? [y/n]: ");
  }
} else {
  $confirm = "y";

  print "-----------------------------------------------------------------------------------------------\n";
  print "NOTICE: The crontab will be cleaned of all SURFids related entries!\n";
  print "-----------------------------------------------------------------------------------------------\n";
}
if ($confirm =~ /^(y|Y)$/) {
  printdelay("Cleaning up the crontab:");
  `cat /etc/crontab | grep -v "$targetdir" >> $rundir/crontab 2>>$logfile`;
  `mv $rundir/crontab /etc/crontab 2>>$logfile`;
  printresult($?);
}

@list = `cat $rundir/files.txt`;
foreach $file (@list) {
  chomp($file);
  printdelay("Removing $file:");
  if (-d "$targetdir/$file") {
    `rm -rf $targetdir/$file 2>>$logfile`;
  } elsif (-e "$targetdir/$file") {
    `rm -f $targetdir/$file 2>>$logfile`;
  }
  printresult($?);
}

printdelay("Removing iptables:");
`rm -f /etc/init.d/iptables.ipvs 2>>$logfile`;
printresult($?);

$confirm = "a";
while ($confirm !~ /^(n|N|y|Y)$/) {
  $confirm = &prompt("Do you want to remove the entire apache2 ssl directory? [y/n]: ");
}
if ($confirm =~ /^(y|Y)$/) {
  printdelay("Removing apache2 ssl certificates:");
  `rm -rf $ssldir/ 2>>$logfile`;
  printresult($?);
}

if (-e "/etc/apache2/sites-enabled/surfnetids-tn-apache.conf") {
  printdelay("Disabling SURFids apache config:");
  `a2dissite surfnetids-tn-apache.conf 2>>$logfile`; 
  printresult($?);
}

if (-e "/etc/apache2/sites-available/surfnetids-tn-apache.conf") {
  printdelay("Removing SURFids apache config:");
  `rm /etc/apache2/sites-available/surfnetids-tn-apache.conf 2>>$logfile`;
  printresult($?);
}

printdelay("Removing xinetd file:");
`rm -f /etc/xinetd.d/openvpn 2>>$logfile`;
printresult($?);

printdelay("Removing openvpn configuration file:");
`rm -f /etc/openvpn/server.conf 2>>$logfile`;
printresult($?);

if (! -e "$targetdir/logtools/") {
  if (! -e "$targetdir/webinterface/") {
    # Tunnel server not installed
    printdelay("Removing license file:");
    `rm $targetdir/LICENSE 2>>$logfile`;
    printresult($?);

    printdelay("Removing changelog file:");
    `rm $targetdir/CHANGELOG 2>>$logfile`;
    printresult($?);

    printdelay("Removing install file:");
    `rm $targetdir/INSTALL 2>>$logfile`;
    printresult($?);
  }
}

if (-e "$targetdir/scripts/") {
  $chk = `ls $targetdir/scripts/ | wc -l`;
  chomp($chk);
  if ($chk == 0) {
    printdelay("Removing scripts directory:");
    `rm -r $targetdir/scripts/ 2>>$logfile`;
    printresult($?);
  }
}

if (-e "/etc/surfnetids/surfnetids-tn.conf") {
  print "The SURFids tunnel server configuration file was not removed!\n";
}
print "Uninstallation complete!\n";

