#!/usr/bin/perl

####################################
# Status check                     #
# SURFids 2.10                     #
# Changeset 001                    #
# 18-06-2008                       #
# Kees Trippelvitz                 #
####################################

#####################
# Changelog:
# 001 Initial release
#####################

@allrules = `ip rule list | grep -v "from all" | awk '{print \$3}'`;
foreach $rule (@allrules) {
    chomp($rule);
    `ip rule del from $rule`;
    if ($? == 0) {
        print "Rule for $rule succesfully deleted!\n";
    } else {
        print "Could not remove rule for $rule!\n";
    }
}
