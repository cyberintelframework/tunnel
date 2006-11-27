#!/usr/bin/perl -w

use POSIX;

# 3.04 validip
# Function to check if a given IP address is a valid IP address.
# Returns 0 if the IP is a valid IP number
# Returns 1 if there are not 4 numbers separated by a dot
# Returns 2 if the first part is not a valid number
# Returns 3 if one of the other parts is not a valid number
# Returns 4 if one of the parts is not a number
sub validip() {
  my ($ip, @ip_ar, $i, $count, $dec);
  $ip = $_[0];
  @ip_ar = split(/\./, $ip);
  $count = @ip_ar;
  if ($count != 4) {
    return 1;
  }
  $i = 0;
  foreach $dec (@ip_ar) {
    if ($dec =~ /^(\d+)$/) {
      if ($i == 0) {
        if ($dec <= 0 || $dec > 255) {
          return 2;
        }
      } else {
        if ($dec < 0 || $dec > 255) {
          return 3;
        }
      }
    } else {
      return 4;
    }
    $i++;
  }
  return 0;
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

return "true";
