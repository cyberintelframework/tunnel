#!/usr/bin/perl -w

####################################
# Scan regex test script           #
# SURFids 3.00                     #
# Changeset 001                    #
# 13-11-2008                       #
# Kees Trippelvitz                 #
####################################

#####################
# Changelog:
# 001 Initial release
#####################

$v = 1;
$b = 1;
$l = 0;
if ($ARGV[0] && $ARGV[0] eq "-v") {
    $b = 0;
}
if ($ARGV[0] && $ARGV[0] eq "-b") {
    $v = 0;
}
if ($ARGV[0] && $ARGV[0] eq "-l") {
    $l = 1;
    $b = 0;
    $v = 0;
}
if ($ARGV[0] && $ARGV[0] eq "-a") {
    $l = 1;
    $b = 1;
    $v = 1;
}
if ($ARGV[0] && $ARGV[0] eq "-h") {
    print "Usage: ./testscan.pl [ -lbvh ]\n";
    print "\n";
    print " -l          Prints all lines ouf output and match checks    [Default: Off]\n";
    print " -b          Prints binary output only                       [Default: On ]\n";
    print " -v          Prints virus output only                        [Default: On ]\n";
    print " -a          Prints all output                               [Default: Off]\n";
    print "\n";
    print "\n";
    print "This script is intended for testing the regular expressions used for extracting \n";
    print "the necessary information from the virus scanners.\n";
    print "Scan a few binaries in the binary directory and save the output in source.txt in the\n";
    print "current directory. Make sure you catch as much different forms of output as possible.\n";
    print "Which means clean binaries as well as malicious binaries.\n";
    print "\n";
    print "You can modify the regular expressions (regexp) in the source code of this script.\n";
    print "  \$getvirus = The regexp to extract the virus. Everything between () will be the virus name.\n";
    print "  \$matchvirus = The regexp to match a line of output with a malicious binary.\n";
    print "  \$getbin = The regexp to extract the binary which has been scanned. Everything between () will be the binary name.\n";
    print "  \$matchclean = The regexp to match a line with a clean binary.\n";
    exit;
}

if (! -e "source.txt") {
    print "Could not find source.txt\n";
    exit 1;
} else {
    @contents = `cat source.txt`;
}

########################################################################
# Regular expressions
########################################################################

$getvirus = '';
$matchvirus = '';
$getbin = '';
$matchclean = '';

########################################################################

foreach $line (@contents) {
    chomp($line);
    if ($line =~ m/$matchvirus/) {
        if ($l == 1) {
            print "Line matched virus regexp!\n";
            print "LINE: $line\n";
        }

        # Extract the virus from the line
        $temp = $line;
        $temp =~ s/$getvirus/$1/;
        $virus = $temp;
        if ($v == 1) {
            print "VIRUS: $virus\n";
        }

        # Extract the binary from the line
        $temp = $line;
        $temp =~ s/$getbin/$1/;
        $binary = $temp;
        if ($b == 1) {
            print "BINARY: $binary\n";
        }
    } elsif ($line =~ m/$matchclean/) {
        if ($l == 1) {
            print "Line matched clean regexp!\n";
            print "LINE: $line\n";
        }

        # Extract the binary from the line
        $temp = $line;
        $temp =~ s/$getbin/$1/;
        $binary = $temp;
        if ($b == 1) {
            print "BINARY: $binary\n";
        }
    } else {
        print "Line did not match anything!\n";
        print "LINE: $line\n";
    }
    print "\n";
}
