#!/usr/bin/perl -w

#########################################
# Update script for SURFnet IDS Sensor	#
# SURFnet IDS                           #
# Version 1.02.18                       #
# 04-09-2006                            #
# Jan van Lith & Kees Trippelvitz	#
#########################################

##################
# Changelog:
# 1.02.18 Rereleased as perl script
# 1.02.17 Fixed a small bug in test of $action 
# 1.02.16 Fixed a bug in the check_ssh grep
# 1.02.15 Changed the way SSH is handled
# 1.02.14 Initial release
##################

################
# Variables    #
################
$basedir = "/cdrom/scripts";
do "$basedir/perl.conf";
require "$basedir/functions.inc.pl";

################
# Start script #
################
printmsg("Starting updates:", "info");
$update = 0;
$menureboot = 0;
$err = 0;
$action = "";

# Check if the disk is read/write.
$chkrw = chkrw();
printmsg("Checking read/write status:", $chkrw);
if ($chkrw != 0) {
  exit;
}

# Check the wget version.
$wgetv = getwgetversion();
if ($wgetv ne "1.9.1") {
  $wgetarg = "--no-check-certificate";
} else {
  $wgetarg = "";
}

# Check if wget authentication is correct.
$chkwgetauth = chkwgetauth($wgetarg);
printmsg("Checking wget authentication:", $chkwgetauth);
if ($chkwgetauth != 0) {
  exit;
}

############
# Updating #
############

# Get the keyname and localip.
$sensor = getsensor();
printmsg("Checking sensor name:", $sensor);
if ($sensor eq "false") {
  exit;
}

$chksensor = chksensorstatus();
if ($chksensor == 0) {
  $if = $br;
} else {
  $if = getif();
}
printmsg("Checking active interface:", $if);

$if_ip = getifip($if);
printmsg("Checking ip address:", $if_ip);

# Check if SSH is running.
$chkssh = chkssh();

# Creating the serverurl
$serverurl = "$http://$server:$port";

# Updating sensor information to the server
`wget -q $wgetarg -O $basedir/update.php "$serverurl/update.php?localip=$if_ip&keyname=$sensor&ssh=$chkssh"`;
printmsg("Updating status information:", $?);

# Check for errors with the localip and tapip update.
$checkerror = `cat $basedir/update.php | grep "ERROR" | wc -l`;
if ($checkerror > 0) {
  # Errors occured while updating localip and tapip.
  $errors = `cat $basedir/update.php | grep "ERROR"`;
  chomp($errors);
  print "${y}An error occurred while updating status information.${n}\n";
  print "${r}$errors${n}\n";
}

# Check if any action was requested.
$action = `cat $basedir/update.php | grep "ACTION:" | awk '{print \$2}'`;
chomp($action);

##########################
# Checking for new files #
##########################

`wget -q $wgetarg -O $basedir/server_version.txt "$serverurl/updates/server_version.txt"`;
printmsg("Retrieving version information:", $?);

# No new sensor image, continue with normal updates.
$total_server = `wc -l $basedir/server_version.txt | cut -d " " -f1`;
$total_sensor = `wc -l $basedir/sensor_version.txt | cut -d " " -f1`;
chomp($total_server);
chomp($total_sensor);
# Check for new files on the server.
if ($total_server != $total_sensor) {
  printmsg("Server has new files available:", "info");

  # For each filename in server_version.txt check if it exists in sensor_version.txt.
  for ($i=1; $i<=$total_server; $i++) {
    # Check if the sensor has the file already.
    $filename_server = `sed -n "$i"p $basedir/server_version.txt | cut -d ":" -f1`;
    chomp($filename_server);
    $check = `grep ${filename_server}: $basedir/sensor_version.txt | wc -l`;
    chomp($check);
    
    if ($check == 0) {
      # The file does not exists in sensor_version.txt.
      # Remove it if it does exists by accident and download a new one.
      `wget -q $wgetarg -O $basedir/${filename_server}.sig $serverurl/updates/${filename_server}.sig`;
      printmsg("Downloading $filename_server:", $?);
      if ($? == 0) {
        `rm -f $basedir/$filename_server`;
	
        # Check the file if it is signed by the scripts certificate.
        `openssl smime -verify -text -inform SMIME -in $basedir/${filename_server}.sig -out $basedir/${filename_server}.new -CAfile $basedir/scripts.crt >/dev/null`;
	printmsg("Checking script signature:", $?);
	
        if ($? == 0) {
          # The file was correctly signed by the scripts certificate.
          # Update sensor_version.txt.
          `rm -f $basedir/${filename_server}.sig`;
          `sed 's/\\r//' $basedir/${filename_server}.new > $basedir/$filename_server`;
          `sed -n "$i"p $basedir/server_version.txt >> $basedir/sensor_version.txt`;
	  printmsg("Updating sensor version info:", $?);
          `rm -f $basedir/${filename_server}.new`;
          `rm -f $basedir/${filename_server}.sig`;
        } else {
          `rm -f $basedir/${filename_server}.new`;
          `rm -f $basedir/${filename_server}.sig`;
        }
      }
    }
  }
}

########################
# Checking for updates #
########################

$tempvers = `mktemp -p $basedir`;
chomp($tempvers);
open(VERS, ">> $tempvers");

# For each file in server_version.txt check version info.
for ($i=1; $i<=$total_server; $i++) {
  # Compare the version of the sensor with the version of the server.
  $filename_server = `sed -n "$i"p $basedir/server_version.txt | cut -d ":" -f1`;
  chomp($filename_server);
  $new_version = `cat $basedir/server_version.txt | grep ${filename_server}: | cut -d ":" -f2`;
  chomp($new_version);
  $old_version = `cat $basedir/sensor_version.txt | grep ${filename_server}: | cut -d ":" -f2`;
  chomp($old_version);
  if ("$new_version" ne "$old_version") {

    # The version info doesn't match, download a new version from the server.
    # The file to be updated is 'update'.
    if ($filename_server eq "update") {
      $touchsig = `mktemp -p $basedir`;
      chomp($touchsig);
      `wget -q $wgetarg -O $touchsig $serverurl/updates/update.sig`;
      printmsg("Downloading new version of update.pl:", $?);
      if ($? == 0) {
        # Download succeeded
        $updatenew = `mktemp -p $basedir`;
	chomp($updatenew);
        `openssl smime -verify -text -inform SMIME -in $touchsig -out $touchnew -CAfile $basedir/scripts.crt >/dev/null`;
        printmsg("Checking script signature:", $?);
        if ($? == 0) {
          # Wait with updating if the filename is the update script itself, but mark it for replacement.
          `rm -f $touchsig`;
	  print VERS "${filename_server}:${new_version}\n";
          $update = 1;
        } else {
          `rm -f $touchsig`;
          `rm -f $touchnew`;
          print VERS "${filename_server}:${old_version}\n";
        }
      }
    # The file to be updated is 'wgetrc'.
    } elsif ($filename_server eq "wgetrc") {
      $touchsig = `mktemp -p $basedir`;
      chomp($touchsig);
      `wget -q $wgetarg -O $touchsig $serverurl/updates/wgetrc.sig`;
      printmsg("Downloading new version of wgetrc:", $?);
      if ($? == 0) {
        $touchnew = `mktemp -p $basedir`;
	chomp($touchnew);
        `openssl smime -verify -text -inform SMIME -in $touchsig -out $touchnew -CAfile $basedir/scripts.crt >/dev/null`;
        printmsg("Checking script signature:", $?);
        if ($? == 0) {
          `rm -f $basedir/wgetrc`;
          `rm -f $touchsig`;
          `sed 's/\\r//' $touchnew > $basedir/wgetrc`;
          `rm -f $touchnew`;
          print VERS "${filename_server}:${new_version}\n";
        } else {
          `rm -f $touchnew`;
          `rm -f $touchsig`;
          print VERS "${filename_server}:${old_version}\n";
        }
      }

    # The file to be updated 'client.conf'.
    } elsif ($filename_server eq "client.conf") {
      $sensor = getsensor();
      printmsg("Retrieving sensor name:", $sensor);
      if ($sensor ne "false") {
        $touchsig = `mktemp -p $basedir`;
	chomp($touchsig);
        `wget -q $wgetarg -O $touchsig $serverurl/updates/client.conf.sig`;
        printmsg("Downloading new version of client.conf:", $?);
        if ($? == 0) {
          $touchnew = `mktemp -p $basedir`;
	  chomp($touchnew);
          `openssl smime -verify -text -inform SMIME -in $touchsig -out $touchnew -CAfile $basedir/scripts.crt >/dev/null`;
          printmsg("Checking script signature:", $?);
          if ($? == 0) {
            # Remove the old client.conf and download a new version.
            `rm -f $basedir/client.conf`;
            `rm -f $touchsig`;
            `sed 's/\\r//' $touchnew > $basedir/client.conf`;
            `rm -f $touchnew`;
            # Update the new client.conf with the ca, key and cert entries needed by OpenVPN.
            open(CLIENT, ">> $basedir/client.conf");
            print CLIENT "ca $basedir/ca.crt\n";
            print CLIENT "key $basedir/$keyname.key\n";
            print CLIENT "cert $basedir/$keyname.crt\n";
            close(CLIENT);
            # Restart the OpenVPN client.
            `$basedir/stopclient.pl`;
            printmsg("Stopping sensor:", $?);
            `$basedir/startclient.pl`;
            printmsg("Starting sensor:", $?);
            print VERS "${filename_server}:${new_version}\n";
          } else {
            `rm -f $touchsig`;
            `rm -f $touchnew`;
            print VERS "${filename_server}:${old_version}\n";
          }
        }
      }
    # The file to be updated not 'idsmenu'.
    } elsif ($filename_server ne "idsmenu") {
      # Download the new file.
      $touchsig = `mktemp -p $basedir`;
      chomp($touchsig);
      `wget -q $wgetarg -O $touchsig $serverurl/updates/${filename_server}.sig`;
      printmsg("Downloading $filename_server:", $?);
      if ($? == 0) {
        $touchnew = `mktemp -p $basedir`;
	chomp($touchnew);
        `openssl smime -verify -text -inform SMIME -in $touchsig -out $touchnew -CAfile $basedir/scripts.crt 2>/dev/null`;
        printmsg("Checking script signature:", $?);
        if ($? == 0) {
          # Remove old file.
          `rm -f $basedir/$filename_server`;
          `rm -f $touchsig`;
          `sed 's/\\r//' $touchnew > $basedir/$filename_server`;
          `rm -f $touchnew`;
          print VERS "${filename_server}:${new_version}\n";
        } else {
          `rm -f $touchsig`;
          `rm -f $touchnew`;
          print VERS "${filename_server}:${old_version}\n";
        }
      }

    # The file to be updated 'idsmenu'.
    } elsif ($filename_server eq "idsmenu") {
      $touchsig = `mktemp -p $basedir`;
      chomp($touchsig);
      `wget -q $wgetarg -O $touchsig $serverurl/updates/idsmenu.sig`;
      printmsg("Downloading $filename_server:", $?);
      if ($? == 0) {
        $touchnew = `mktemp -p $basedir`;
	chomp($touchnew);
        `openssl smime -verify -text -inform SMIME -in $touchsig -out $touchnew -CAfile $basedir/scripts.crt >/dev/null`;
        printmsg("Downloading $filename_server:", $?);
        if ($? == 0) {
          `killall -9 idsmenu`;
          `rm -f $basedir/idsmenu`;
          `rm -f $touchsig`;
          `sed 's/\\r//' $touchnew > $basedir/idsmenu`;
          `rm -f $touchnew`;
          print VERS "${filename_server}:${new_version}\n";
        } else {
          `rm -f $touchsig`;
          `rm -f $touchnew`;
          print VERS "${filename_server}:${old_version}\n";
        }
      }
    }
  } else {
    print VERS "${filename_server}:${old_version}\n";
  }
}
close(VERS);
# Update sensor_version.txt.
`mv -f $tempvers $basedir/sensor_version.txt`;
printmsg("Updating sensor version information:", $?);

################
# Action check #
################

if ($checkerror == 0) {
  if ($action eq "SSHON") {
    `/etc/init.d/ssh start`;
    printmsg("Server request - start SSH:", $?);
  } elsif ($action eq "SSHOFF") {
    `killall sshd`;
    printmsg("Server request - stop SSH:", $?);
  } elsif ($action eq "CLIENT") {
    $status = `cat $basedir/update.php | grep "STATUS: " | awk '{print \$2}'`;
    chomp($status);
    if ($status == 0) {
      `sh $basedir/startclient 0`;
      printmsg("Server request - start sensor:", $?);
    } else {
      `sh $basedir/stopclient`;
      printmsg("Server request - stop sensor:", $?);
    }
  } elsif ($action eq "RESTART") {
    `sh $basedir/stopclient`;
    printmsg("Server request - restart sensor - stopping:", $?);
    `sh $basedir/startclient 0`;
    printmsg("Server request - restart sensor - starting:", $?);
  } elsif ($action eq "BLOCK") {
    $status = `cat $basedir/update.php | grep "STATUS: " | awk '{print \$2}'`;
    chomp($status);
    $i = 0;
    if ($status == "2") {
      `mv $basedir/$keyname.bcrt $basedir/$keyname.crt`;
      if ($? != 0) { $i++ };
      `mv $basedir/$keyname.bkey $basedir/$keyname.key`;
      if ($? != 0) { $i++ };
      `chmod 600 $basedir/$keyname.key`;
      if ($? != 0) { $i++ };
      `chmod 644 $basedir/$keyname.crt`;
      if ($? != 0) { $i++ };
      printmsg("Server request - enable client:", $i);
    } else {
      `$basedir/stopclient`;
      if ($? != 0) { $i++ };
      `cp $basedir/$keyname.crt $basedir/$keyname.bcrt`;
      if ($? != 0) { $i++ };
      `cp $basedir/$keyname.key $basedir/$keyname.bkey`;
      if ($? != 0) { $i++ };
      `echo "DISABLED" > $basedir/$keyname.crt`;
      if ($? != 0) { $i++ };
      `echo "DISABLED" > $basedir/$keyname.key`;
      if ($? != 0) { $i++ };
      `chmod 600 $basedir/$keyname.bkey`;
      if ($? != 0) { $i++ };
      `chmod 600 $basedir/$keyname.bcrt`;
      if ($? != 0) { $i++ };
      printmsg("Server request - disable client:", $i);
    }    
  }
}

if ($checkerror == 0) {
  $oldserver = `cat $basedir/client.conf | grep "remote " | awk '{print \$2}'`;
  $newserver = `cat $basedir/update.php | grep "SERVER: " | awk '{print \$2}'`;
  chomp($oldserver);
  chomp($newserver);
  if ($newserver) {
    if ("$newserver" ne "$oldserver") {
      $touchconf = `mktemp -p $basedir`;
      chomp($touchconf);
      `sed "s/^remote.*\$/remote $newserver/" $basedir/client.conf > $touchconf`;
      `mv -f $touchconf $basedir/client.conf`;
    }
  }
}

# Remove trash files.
`rm -f $basedir/tmp.*`;
`rm -f $basedir/server_version.txt`;
printmsg("Removing temporary files:", $?);

if ($update == 1) {
  # If there is a newer version of the update script start update_remove.
  exec("$basedir/update_remove $updatenew");
} else {
  printmsg("Updates complete!", "info");
}
if ("$action" eq "REBOOT") {
  printmsg("Server request - Reboot", "info");
  `init 6`;
}
