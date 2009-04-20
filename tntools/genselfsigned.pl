#!/usr/bin/perl

use POSIX;

$ssldir = "/etc/apache2/surfidsssl/";
$key_size = 1024;

# 3.01 prompt
# Function to prompt the user for input
sub prompt {
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
sub printmsg {
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

# 3.12 printdelay
# Function to print status message
sub printdelay {
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
sub printresult {
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

# Color codes
$n = "\033[0;39m";
$y = "\033[1;33m";
$r = "\033[1;31m";
$g = "\033[1;32m";

$server = "";
while ($server eq "") {
    $server = &prompt("Enter the hostname or IP address of the server that this certificate is for: ");
}

if (! -d "$ssldir") {
    printdelay("Creating apache2 ssl directory:");
    `mkdir $ssldir`;
    printresult($?);
}

if (! -e "$ssldir/ca.key") {
    print "##########################################\n";
    print "########## Generating ROOT CA ############\n";
    print "##########################################\n";
    printmsg("Generating root CA certificate key:", "info");
    `openssl genrsa -des3 -out $ssldir/ca.key $key_size`;
    print "\n";
    printmsg("Generating root CA certificate:", "info");
    print "${r}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${n}\n";
    printmsg("    The Common Name should be:", "$server CA");
    print "${r}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${n}\n";
    `openssl req -new -x509 -days 365 -key $ssldir/ca.key -out $ssldir/ca.crt`;
} else {
    print "$ssldir/ca.key already exists!\n";
}
if (! -e "$ssldir/key.pem") {
    print "\n";
    print "##########################################\n";
    print "######## Generating Server Certs #########\n";
    print "##########################################\n";
    printmsg("Generating server key:", "info");
    `openssl genrsa -des3 -out $ssldir/key.pem $key_size`;

    print "\n";
    printmsg("Generating signing request:", "info");
    print "${r}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${n}\n";
    printmsg("    The Common Name should be:", "$server");
    print "${r}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${n}\n";
    print "You should use the same information you have used for the CA certificate except\n";
    print "for the common name as stated above.\n\n";
    `openssl req -new -key $ssldir/key.pem -out $ssldir/request.pem`;

    print "\n";
    printmsg("Generating server certificate:", "info");
    `openssl x509 -req -days 365 -in $ssldir/request.pem -CA $ssldir/ca.crt -CAkey $ssldir/ca.key -set_serial 01 -out $ssldir/cert.pem`;
    printmsg("Finishing certificate generation:", "info");
    `openssl rsa -in $ssldir/key.pem -out $ssldir/key.pem.insecure`;
    `mv $ssldir/key.pem $ssldir/key.pem.secure`;
    `mv $ssldir/key.pem.insecure $ssldir/key.pem`;
} else {
    print "$ssldir/key.pem already exists!\n";
}

