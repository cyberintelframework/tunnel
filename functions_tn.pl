#!/usr/bin/perl

####################################
# Installation script              #
# SURFnet IDS                      #
# Version 2.00.01                  #
# 14-09-2007                       #
# Jan van Lith & Kees Trippelvitz  #
####################################

###############################################
# Changelog:
# 2.00.01 version 2.00
# 1.04.02 Fixed getcrtvalue bug with localities/states containing a space
# 1.04.01 Initial release
###############################################

use POSIX;

# 1.01 rmsvn
# Function to remove the remaining .svn directories
sub rmsvn() {
  my ($chk, $dir, $newdir, $file);
  $dir = $_[0];
  chomp($dir);
  opendir(DH, $dir);
  foreach (readdir(DH)) {
    $file = $_;
    chomp($file);
    if ($file !~ /^(\.|\.\.)$/) {
      if ($file ne "svnroot") {
        if (-d "$dir$file") {
          if ($file =~ /^\.svn$/) {
            `rm -r $dir$file/`;
          } else {
            $newdir = "$dir$file/";
            &rmsvn($newdir);
          }
        }
      }
    }
  }
  closedir(DH);
}

# 1.03 checkcron
# Function to check if a certain cron rule is already in the crontab
# Returns amount of cronrules found
sub checkcron() {
  my ($chk, $cronrule);
  $cronrule = $_[0];
  chomp($cronrule);
  $chk = `cat /etc/crontab | grep $cronrule | wc -l`;
  chomp($chk);
  return $chk;
}

# 2.01 getcrtvalue
# Function to retrieve a value from the ca.crt
sub getcrtvalue() {
  my ($target, @target_ar, @issuer_ar, $issuer, $key, $value);
  $target = $_[0];
  chomp($target);
  if (-r "$targetdir/serverkeys/ca.crt") {
    $issuer = `cat $targetdir/serverkeys/ca.crt | grep "Issuer"`;
    chomp($issuer);
    $issuer =~ s/        Issuer: //;
    @issuer_ar = split(/\,/, $issuer);
    foreach (@issuer_ar) {
      chomp();
      s/,$//;
      @target_ar = split(/=/, $_);
      $key = $target_ar[0];
      $key =~ s/ //g;
      if ($key eq $target) {
        if ($key eq "CN") {
          $value = $target_ar[2];
        } else {
          $value = $target_ar[1];
        }
        return $value;
      }
    }
  } else {
    return "";
  }
  return "";
}

# 3.01 prompt
# Function to prompt the user for input
sub prompt() {
  my ($promptstring, $defaultvalue);
  ($promptstring,$defaultvalue) = @_;
  if ($defaultvalue) {
    #print $promptstring, "[", $defaultvalue, "]: ";
    print $promptstring;
  } else {
    $defaultvalue = "";
    print $promptstring;
  }
  $| = 1;       # force a flush after our print
  $_ = <STDIN>; # get the input from STDIN

  chomp;

  if ("$defaultvalue") {
    if ($_ eq "") {
      return $defaultvalue;
    } else {
      return "$_";
    }
  } else {
    return "$_";
  }
}

# 3.02 printmsg
# Function to print status message
sub printmsg() {
  my ($msg, $ec, $len, $tabcount, $tabstring);
  $msg = $_[0];
  chomp($msg);
  $ec = $_[1];
  chomp($ec);
  $len = length($msg);
  $tabcount = ceil((64 - $len) / 8);
  $tabstring = "\t" x $tabcount;
  if ("$ec" eq "0") {
    print $msg . $tabstring . "[${g}OK${n}]\n";
  } elsif ($ec eq "false" || $ec eq "filtered") {
    print $msg . $tabstring . "[${r}Failed${n}]\n";
  } elsif ($ec eq "warning") {
    print $msg . $tabstring . "[${r}Warning${n}]\n";
  } elsif ($ec =~ /^([0-9]*)$/) {
    print $msg . $tabstring . "[${r}Failed (error: $ec)${n}]\n";
  } elsif ($ec eq "ignore") {
    print $msg . $tabstring . "[${y}ignore${n}]\n";
  } elsif ($ec eq "info") {
    print $msg . $tabstring . "[${y}info${n}]\n";
  } else {
    print $msg . $tabstring . "[${g}$ec${n}]\n";
  }
}

# 3.04 validip
# Function to check if a given IP address is a valid IP address.
# Returns 0 if the IP is a valid IP number
# Returns 1 if not
sub validip() {
  my ($ip, @ip_ar, $i, $count, $dec);
  $ip = $_[0];
  chomp($ip);
  $regexp = "^([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))";
  $regexp .= "\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))";
  $regexp .= "\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))";
  $regexp .= "\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\$";
  if ($ip !~ /$regexp/) {
    return 1;
  } else {
    return 0;
  }
  return 1;
}

# 3.12 printdelay
# Function to print status message
sub printdelay() {
  my ($msg, $len, $tabcount, $tabstring);
  $msg = $_[0];
  chomp($msg);
  $len = length($msg);
  $tabcount = ceil((64 - $len) / 8);
  $tabstring = "\t" x $tabcount;
  print $msg . $tabstring;
  return 0;
}

# 3.13 printresult
# Function to print the result of an action.
# Used along with printdelay
sub printresult() {
  my ($ec);
  $ec = $_[0];
  chomp($ec);
  if ("$ec" eq "0") {
    print "[${g}OK${n}]\n";
  } elsif ($ec eq "false" || $ec eq "filtered") {
    print "[${r}Failed${n}]\n";
  } elsif ($ec =~ /^[-]?(\d+)$/) {
    print "[${r}Failed (error: $ec)${n}]\n";
  } elsif ($ec eq "ignore") {
    print "[${y}ignore${n}]\n";
  } elsif ($ec eq "info") {
    print "[${y}info${n}]\n";
  } else {
    print "[${g}$ec${n}]\n";
  }
  return 0;
}

return "true";
