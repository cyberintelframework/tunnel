#!/usr/bin/perl

####################################
# Scanbinaries script              #
# SURFids 3.00                     #
# Changeset 006                    #
# 10-07-2009                       #
# Jan van Lith & Kees Trippelvitz  #
####################################

#####################
# Changelog:
# 006 Fixed bugs #149 and #150
# 005 Added ClamAV and fixed version commands
# 004 Revised the logic, should perform better now
# 003 Added more scan methods
# 002 Added scan method support
# 001 version 2.10.00 release
#####################

####################
# Modules used
####################
use DBI;
use Time::localtime qw(localtime);

##################
# Variables used
##################
do '/etc/surfnetids/surfnetids-tn.conf';
require "$c_surfidsdir/scripts/tnfunctions.inc.pl";
%scanners = ();

####################
# Define scanners
####################
$scanners->{"F-Prot"} = {
            'cmd' => "/opt/f-prot/fpscan -v 2 --report --adware",
            'update' => "/opt/f-prot/fpupdate",
            'version' => "/opt/f-prot/fpscan --version | grep \"F-PROT Antivirus version\" | awk -F'(' '{print \$1}' | awk '{print \$NF}'",
            'batchmode' => 0,
};
$scanners->{"AVAST"} = {
            'cmd' => "/opt/avast4workstation-1.0.8/bin/avast -n",
            'update' => "/opt/avast4workstation-1.0.8/bin/avast-update",
            'version' => "/opt/avast4workstation-1.0.8/bin/avast --version | head -n1 | awk -F\"avast \" '{print \$2}'",
            'batchmode' => 1,
};
$scanners->{"ClamAV"} = {
            'cmd' => "clamscan --no-summary",
            'update' => "freshclam",
            'version' => "clamscan --version | awk '{print \$2}' | awk -F\"/\" '{print \$1}'",
            'batchmode' => 0,
};

##################
# Functions
##################

##################
# Main script
##################

# Connect to the database (dbh = DatabaseHandler or linkserver)
$checkdb = dbconnect();

@contents = ();
if ($c_scan_method == 0) {
    print "Scanning all binaries\n";
    # Scan all binaries

    # Getting bindir contents
    opendir BINDIR, $c_bindir;
    @contents = grep !/^\.\.?$/, readdir BINDIR;
} elsif ($c_scan_method == 1) {
    # Scan only new malware
    print "Scanning new binaries only\n";

    # First define the set of binaries that already have been scanned
    $sql_scanned = "SELECT DISTINCT uniq_binaries.name FROM uniq_binaries ";
    $sql_scanned .= " INNER JOIN binaries ON uniq_binaries.id = binaries.bin ";
    $sth_scanned = $dbh->prepare($sql_scanned);
    $result_scanned = $sth_scanned->execute();
    %scanned = ();
    while (@rs = $sth_scanned->fetchrow_array) {
        $binary = $rs[0];
        $scanned{$binary} = 1;
    }

    # Now get all the existing binaries on the system
    opendir BINDIR, $c_bindir;
    @dircontents = grep !/^\.\.?$/, readdir BINDIR;

    # Now subtract the scanned binaries from the dircontents dataset
    foreach $bin (@dircontents) {
        if (! exists $scanned{$bin}) {
            push(@contents, $bin);
        }
    }
} elsif ($c_scan_method == 2) {
    # Scan only new malware and undetected/suspicious malware
    print "Scanning new binaries and undetected binaries only\n";

    # First define the set of binaries that already have been scanned and are known
    $sql_known = "SELECT DISTINCT uniq_binaries.name FROM uniq_binaries ";
    $sql_known .= " INNER JOIN binaries ON uniq_binaries.id = binaries.bin ";
    $sql_known .= " INNER JOIN stats_virus ON binaries.info = stats_virus.id ";
    $sql_known .= " AND NOT stats_virus.name = 'Suspicious' ";
    $sth_known = $dbh->prepare($sql_known);
    $result_known = $sth_known->execute();
    %known = ();
    while (@rs = $sth_known->fetchrow_array) {
        $binary = $rs[0];
        $known{$binary} = 1;
    }

    # Now get all the existing binaries on the system
    opendir BINDIR, $c_bindir;
    @dircontents = grep !/^\.\.?$/, readdir BINDIR;

    # Now subtract the known binaries from the dircontents dataset
    foreach $bin (@dircontents) {
        if (! exists $known{$bin}) {
            push(@contents, $bin);
        }
    }
} elsif ($c_scan_method == 3) {
    # Scan only new malware and undetected/suspicious malware and all binaries with limitation
    print "Scanning new, undetected and all binaries (limited)\n";    

    # First define the set of binaries that already have been scanned and are known
    $sql_known = "SELECT DISTINCT uniq_binaries.name FROM uniq_binaries ";
    $sql_known .= " INNER JOIN binaries ON uniq_binaries.id = binaries.bin ";
    $sql_known .= " INNER JOIN stats_virus ON binaries.info = stats_virus.id ";
    $sql_known .= " AND NOT stats_virus.name = 'Suspicious' ";
    $sth_known = $dbh->prepare($sql_known);
    $result_known = $sth_known->execute();
    %known = ();
    while (@rs = $sth_known->fetchrow_array) {
        $binary = $rs[0];
        $known{$binary} = 1;
    }

    # Now get all the existing binaries on the system
    opendir BINDIR, $c_bindir;
    @dircontents = grep !/^\.\.?$/, readdir BINDIR;

    # Now subtract the known binaries from the dircontents dataset
    $limit_counter = 0;
    foreach $bin (@dircontents) {
        if (! exists $known{$bin}) {
            push(@contents, $bin);
        } else {
            # If the scan_period_limit hasn't been reached, check period
            if ($c_scan_period_limit == 0) {
              push(@contents, $file);
            } elsif ($limit_counter != $c_scan_period_limit) {
                # Check the c_scan_period threshold
                $period_check = `find ${c_bindir}/$bin -amin +$c_scan_period | wc -l`;
                
                if ($period_check == 1) {
                    # If above threshold, add to contents
                    $limit_counter++;
                    push(@contents, $file);
                }
            }
        }
    }
} else {
    # Unknown scan method

    # If a command line file has been given, scan that instead
    # Mainly intended for manual scans, not for automated scans
    if (@ARGV) {
        @contents = @ARGV;
    } else {
        print "Unknown scanning method! Exiting...\n";
        exit;
    }
}

# If a command line file has been given, scan that instead
# Mainly intended for manual scans, not for automated scans
if (@ARGV) {
    @contents = @ARGV;
}

# Serialize the contents array
$files = "";
$total_files = 0;
@sep_files = ();
$a = 0;
foreach $file (@contents) {
    if ($a == $c_scan_batch_max) {
      push(@sep_files, $files);
      $files = "";
      $a = 0;
    }
    $a++;
    # Serialize it
    $files .= " $file";
    $allfiles .= " $file";
    $total_files++;
    
    # Now take care of the uniq_binaries and binaries_detail tables
    # FIXME: Could possibly moved upwards at the stage of defining contents
    #        There we know the set of known and unknown binaries

    ##############
    # UNIQ_BINARIES
    ##############
    # Check if the binary was already in the uniq_binaries table.
    $chk = dbnumrows("SELECT id FROM uniq_binaries WHERE name = '$file'");
    if ($chk == 0) {
        print "[Binary] Adding new binary\n";

        $chk = dbquery("INSERT INTO uniq_binaries (name) VALUES ('$file')");
    }

    # Get the ID of the binary
    $sth = dbquery("SELECT id FROM uniq_binaries WHERE name = '$file'");
    @row = $sth->fetchrow_array;
    $bid = $row[0];

    ##############
    # BINARIES_DETAIL
    ##############
    # Check if the binary was already in the binaries_detail table.
    $chk = dbnumrows("SELECT bin FROM binaries_detail WHERE bin = $bid");
    if ($chk == 0) {

        # Getting the info from linux file command.
        $filepath = "$c_bindir/$file";
        $fileinfo = `file $filepath`;
        @fileinfo = split(/:/, $fileinfo);
        $fileinfo = $fileinfo[1];
        chomp($fileinfo);

        # Getting the file size.
        $filesize = (stat($filepath))[7];
        $chk = dbquery("INSERT INTO binaries_detail (bin, fileinfo, filesize) VALUES ($bid, '$fileinfo', $filesize)");
        print "[Detail] Adding new detail record\n";
    }

    #############
    # UPX
    #############
    # Check the UPX result and add it if necessary
#    if ($c_scan_upx == 1) {
#        $filepath = "$c_bindir/$file";
#        $status = `upx -t $filepath | grep $file | awk '{print \$3}'`;
#    }
}

# Before scanning check if the virusname Suspicious is in the database
# If not, add it. No need to do this every time a file is scanned
$chk = dbnumrows("SELECT id FROM stats_virus WHERE name = 'Suspicious'");
if ($chk == 0) {
    $chk = dbquery("INSERT INTO stats_virus (name) VALUES ('Suspicious')");
}

# Store the Suspicious virus ID for later use
$suspicious = 0;
$sth = dbquery("SELECT id FROM stats_virus WHERE name = 'Suspicious'");
if ($sth ne "false") {
  @row = $sth->fetchrow_array;
  $suspicious = $row[0];
}

%results = ();
while ( my ($name, $config) = each(%$scanners) ) {
    if (!$scanners->{$name}->{count}) {
        $scanners->{$name}->{count} = 0;
    }
    $cmd = $scanners->{$name}->{'cmd'};
    $cmd =~ s/!bindir!/$c_bindir/g;
    $cmd =~ s/!file!/$file/g;

    $sth = dbquery("SELECT id, matchvirus, matchclean, getvirus, getbin, status FROM scanners WHERE name = '$name'");
    @row = $sth->fetchrow_array;
    $vid = $row[0];
    $matchvirus = $row[1];
    $matchclean = $row[2];
    $getvirus = $row[3];
    $getbin = $row[4];
    $status = $row[5];

    if ($matchvirus ne "" && $getvirus ne "" && $getbin ne "" && $matchclean ne "" && $vid ne "" && $status == 1) {
        chdir($c_bindir);
        if ($scanners->{$name}->{'batchmode'} == 1) {
            print "$name scanning in batch mode!\n";
            foreach $file_set (@sep_files) {
                @cmd_output = `$cmd $file_set`;
                push(@scanner_output, @cmd_output);
            }
        } else {
            print "$name scanning all at once!\n";
            @scanner_output = `$cmd $allfiles`;
        }

        foreach $line (@scanner_output) {
            chomp($line);
            if ($line =~ m/$matchvirus/) {
                # Extract the virus from the line
                $temp = $line;
                $temp =~ s/$getvirus/$1/;
                $virus = $temp;

                # Extract the binary from the line
                $temp = $line;
                $temp =~ s/$getbin/$1/;
                $binary = $temp;

                if (exists $results{$binary}) {
                    print "Skipping $binary - OLD: ". $results{$binary} ." - NEW: $virus\n";
                    next;
                }

                $results{$binary} = $virus;
                
                # Get the virus ID
                $chk = dbnumrows("SELECT id FROM stats_virus WHERE name = '$virus'");
                if ($chk == 0) {
                    $chk = dbquery("INSERT INTO stats_virus (name) VALUES ('$virus')");
                    print "[Virus] Adding new virus\n";
                }

                $sth = dbquery("SELECT id FROM stats_virus WHERE name = '$virus'");
                @row = $sth->fetchrow_array;
                $vid = $row[0];

                # Get the binary ID
                print "BINARY: $binary\n";
                $sth = dbquery("SELECT id FROM uniq_binaries WHERE name = '$binary'");
                @row = $sth->fetchrow_array;
                $bid = $row[0];

                print "\t$name:\t\t$virus ($vid)\n";

                if ($bid ne "" && $vid ne "" && $sid ne "") {
                    # We check if this binary and the scan result were already in the database. The unique key here is $file, $scanner, $virus.
                    print "A\n";
                    $chk = dbnumrows("SELECT bin FROM binaries WHERE bin = $bid AND info = $vid AND scanner = $sid");
                    if ($chk == 0) {
                        # The combination of $file, $scanner and $virus was not yet in the database. Insert it.
                        $scanners->{$name}->{count}++;
                        print "B\n";
                        $chk = dbquery("INSERT INTO binaries (timestamp, bin, info, scanner) VALUES ($time, $bin_id, $virus_id, $key)");
                        print "[Scan] Adding new scan record\n";
                    }
                }

                # Update the last scanned timestamp
                $ts = time();
                $chk = dbquery("UPDATE binaries_detail SET last_scanned = $ts WHERE bin = $bid");
            } elsif ($line =~ m/$matchclean/) {
                # Extract the binary from the line
                $temp = $line;
                $temp =~ s/$getbin/$1/;
                $binary = $temp;

                if (exists $results{$binary}) {
                    print "Skipping $binary - OLD: ". $results{$binary} ." - NEW: OK\n";
                    next;
                }

                $results{$binary} = "OK";

                # Get the binary ID
                $sth = dbquery("SELECT id FROM uniq_binaries WHERE name = '$binary'");
                @row = $sth->fetchrow_array;
                $bid = $row[0];

                if ($bid ne "" && $sid ne "" && $vid != 0) {
                    # We check if this binary and the scan result were already in the database. The unique key here is $file, $scanner, $virus.
                    $chk = dbnumrows("SELECT bin FROM binaries WHERE bin = $bid AND info = $vid AND scanner = $sid");
                    if ($chk == 0) {
                        # The combination of $file, $scanner and $virus was not yet in the database. Insert it.
                        $scanners->{$name}->{count}++;
                        $chk = dbquery("INSERT INTO binaries (timestamp, bin, info, scanner) VALUES ($time, $bin_id, $virus_id, $key)");
                        print "[Scan] Adding new scan record\n";
                    }
                }

                # Update the last scanned timestamp
                $ts = time();
                $chk = dbquery("UPDATE binaries_detail SET last_scanned = $ts WHERE bin = $bid");
            }
        }
    }
}

# Print a total overview of the scan results.
print "Scanned files: $total_files\n";

while ( my ($name, $config) = each(%$scanners) ) {
    $count = $scanners->{$name}->{count};
    print "$name new: $count\n";
}

exit;
foreach $file ( @contents ) {

    $time = time();
    $sql_time = "UPDATE binaries_detail SET last_scanned = $time WHERE bin = $bin_id";
    $sth_time = $dbh->prepare($sql_time);
    $result_time = $sth_time->execute();

    print "Scanning $file - ID: $bin_id\n";
    $total_files++;
    for my $key ( keys %scanners ) {
        $name = $scanners{$key}{name};
        if (!$scanners{$key}{count}) {
            $scanners{$key}{count} = 0;
        }
        $cmd = $scanners{$key}{command};
        $cmd =~ s/!bindir!/$c_bindir/g;
        $cmd =~ s/!file!/$file/g;
        $virus = `$cmd`;
        chomp($virus);
        if ($virus eq "") {
            $virus = "Suspicious";
        }

        $sql_virus = "SELECT id FROM stats_virus WHERE name = '$virus'";
        $sth_virus = $dbh->prepare($sql_virus);
        $result_virus = $sth_virus->execute();
        if ($result_virus == 0) {
            # The virus was not yet in the stats_virus table. Insert it.
            $sql_insert = "INSERT INTO stats_virus (name) VALUES ('$virus')";
            $sth_insert = $dbh->prepare($sql_insert);
            $result_insert = $sth_insert->execute();

            $sql_virus = "SELECT id FROM stats_virus WHERE name = '$virus'";
            $sth_virus = $dbh->prepare($sql_virus);
            $result_virus = $sth_virus->execute();
        }
        @temp = $sth_virus->fetchrow_array;
        $virus_id = $temp[0];
        print "\t$name:\t\t$virus ($virus_id)\n";

        # We check if this binary and the scan result were already in the database. The unique key here is $file, $scanner, $virus.
        $sql_select = "SELECT * FROM binaries WHERE bin = $bin_id AND info = $virus_id AND scanner = $key";
        $sth_select = $dbh->prepare($sql_select);
        $result_select = $sth_select->execute();
        $numrows_select = $sth_select->rows;
        if ($numrows_select == 0) {
            # The combination of $file, $scanner and $virus was not yet in the database. Insert it.
            $scanners{$key}{count}++;
            $sql_insert = "INSERT INTO binaries (timestamp, bin, info, scanner) VALUES ($time, $bin_id, $virus_id, $key)";
            $sth_insert = $dbh->prepare($sql_insert);
            $result_insert = $sth_insert->execute();
        }
    }
}

# Print a total overview of the scan results.
print "Scanned files: $total_files\n";

for $key ( keys %scanners ) {
    $name = $scanners{$key}{name};
    $count = $scanners{$key}{count};
    print "$name new: $count\n";
}

closedir BINDIR;
$dbh = "";
close(LOG);
