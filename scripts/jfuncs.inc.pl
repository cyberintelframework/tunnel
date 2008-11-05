#!/usr/bin/perl -w

use POSIX;

# 0.01 connectdb
# 0.02 printlog
# 0.03 getts
# 0.04 logmsg
# 1.01 chkif
# 1.02 getifip
# 1.03 getalltap
# 1.04 getif
# 2.01 getallroutes
# 2.02 chkroute
# 2.03 delroute
# 2.04 addroute
# 3.01 addrule
# 3.02 chkrule_by_ip
# 3.03 chkrule_by_if
# 3.04 chkrule
# 3.05 delrule_by_ip
# 3.06 delrule_by_if
# 3.07 getallrules
# 4.33 logsys

# 0.01 connectdb
# Function to connect to the database
# Returns "true" on success
# Returns "false" on failure
sub connectdb() {
  my ($pgerr);
  $dbh = DBI->connect($c_dsn, $c_pgsql_user, $c_pgsql_pass)
          or $pgerr = $DBI::errstr;
  if ($dbh ne "") {
    return "true", "Connecting to the database: OK!";
  } else {
    chomp($pgerr);
    return "false", $pgerr;
  }
}

# 0.02 printlog
# Function to print something to a logfile
# Returns 0 on success
# Returns 1 on failure
sub printlog() {
  my ($err, $ts, $msg, $logstring);
  $msg = $_[0];
  $err = $_[1];
  $ts = getts();
  $logstring = "[$ts";
  if ($tap) {
    if ($tap ne "") {
      $logstring .= " - $tap";
    }
  }
  if ($err) {
    if ("$err" ne "") {
      $logstring .= " - $err";
    }
  }
  $logstring .= "] $msg\n";
  print "$logstring\n";
}

# 0.03 getts
# Function to get the current date in a human readable format
# Returns date as "day-month-year hour:min:sec"
sub getts() {
  my ($ts, $year, $month, $day, $hour, $min, $sec, $timestamp);
  $ts = time();
  $year = localtime->year() + 1900;
  $month = localtime->mon() + 1;
  if ($month < 10) {
    $month = "0" . $month;
  }
  $day = localtime->mday();
  if ($day < 10) {
    $day = "0" . $day;
  }
  $hour = localtime->hour();
  if ($hour < 10) {
    $hour = "0" . $hour;
  }
  $min = localtime->min();
  if ($min < 10) {
    $min = "0" . $min;
  }
  $sec = localtime->sec();
  if ($sec < 10) {
    $sec = "0" . $sec;
  }

  $timestamp = "$day-$month-$year $hour:$min:$sec";
}

# 0.04 logmsg
# Function to print a message including error if needed
sub logmsg() {
  my ($chk, $err, $msg, $ss, $tabstring, $tabcount, $len);
  $chk = $_[0];
  $err = $_[1];
  $msg = $_[2];

  $len = length($msg);
  $tabcount = ceil((40 - $len) / 8);
  $tabstring = "\t" x $tabcount;
  $ss = "[$sensor]\t";

  if ("$chk" eq "false") {
    print $ss . $msg . $tabstring ."${r}Fail${n}\n";
    print "\t\t" .$err. "\n";
  } elsif ("$chk" eq "skip") {
    print $ss . $msg . $tabstring  ."${y}Skip${n}\n";
  } else {
    if ($verbose > 0) {
      print $ss . $msg . $tabstring ."${g}OK${n}\n";
      if ($verbose == 2) {
        print "\t\t" .$err. "\n";
      }
    }
  }
}

#########################
# INTERFACE FUNCTIONS
#########################

# 1.01 chkif
# Function to check the existance of an interface
sub chkif() {
  my ($if);
  if (!$_[0]) {
    return "false", "Given interface argument was empty!";
  }
  $if = $_[0];
  chomp($if);
  if ("$if" eq "" ) {
    return "false", "Given interface argument was empty!";
  } else {
    `ifconfig $if >/dev/null 2>/dev/null`;
    if ($? == 0) {
      return "true", "Interface $if exists!";
    } else {
      return "false", "Interface $if did not exist!";
    }
  }
}

# 1.02 getifip
# Function to get the IP address of a given interface
sub getifip() {
  my ($if, $ifip, $chkif, $err);
  if (!$_[0]) {
    return "false", "Given interface argument was empty!";
  }
  $if = $_[0];
  ($chkif, $err) = \&chkif($if);
  if ($chkif eq "false") {
    return "false", $err;
  }

  $ifip = `ifconfig $if | grep "inet addr" | awk '{print \$2}' | awk -F: '{print \$2}' 2>/dev/null`;
  chomp($ifip);
  if ($? != 0) {
    return "false", "Failed to run ifconfig for interface: $if";
  } else {
    if ($ifip eq "") {
      return "false", "Interface $if did not have an IP address!";
    } else {
      return "true", "Succesfully retrieved interface address!", $ifip;
    }
  }
}

# 1.03 getalltap
# Function to get all tap interfaces
sub getalltap() {
  my(@tapifaces);
  @tapifaces = `ifconfig -a | grep -A1 tap | grep "inet addr" | awk '{print \$2}' | awk -F: '{print \$2}' 2>/dev/null`;
  if ($? != 0) {
    return "false", "Failed to run ifconfig!";
  } else {
    return "true", "Retrieving all tap interfaces: OK!", @tapifaces;
  }
}

# 1.04 getif
# Function to get the interface name when given an IP address
sub getif() {
  my ($if, $ifip);
  if (!$_[0]) {
    return "false", "Given IP address was empty!";
  }
  $ifip = $_[0];
  chomp($ifip);

  if ("$ifip" eq "" ) {
    return "false", "Cannot get interface with empty IP address!";
  }
  $if = `ifconfig -a | grep -B1 "$ifip " | grep tap | awk '{print \$1}'`;
  chomp($if);
  if ($? != 0) {
    return "false", "Could not execute ifconfig command!";
  } else {
    if ("$if" eq "") {
      return "false", "Could not find interface!";
    } else {
      return "true", "Retrieving interface: OK!", $if;
    }
  }
}

#########################
# ROUTE FUNCTIONS
#########################

# 2.01 getallroutes
# Function to get all the routes present in the main routing table
sub getallroutes() {
  my(@routes);
  @routes = `ip route list | grep -v scope | grep -v default | awk '{print \$1}' 2>/dev/null`;
  if ($? != 0) {
    return "false", "Listing all ip routes failed! Has iproute been installed?";
  } else {
    return "true", "Retrieving all routes: OK!", @routes;
  }
}

# 2.02 chkroute
# Function to check if a route exists in a given table
sub chkroute() {
  my ($route, $table, $chkroute);
  if (!$_[0]) {
    return "false", "Given route argument was empty!";
  }
  if (!$_[1]) {
    return "false", "Given table argument was empty!";
  }
  $route = $_[0];
  $table = $_[1];
  chomp($route);
  chomp($table);
  if ("$route" eq "") {
    return "false", "Cannot check empty route!";
  }
  if ("$table" eq "") {
    return "false", "Cannot check route for empty table!";
  }
  $chkroute = `ip route list table $table | grep $route | wc -l 2>/dev/null`;
  chomp($chkroute);
  if ($? != 0) {
    return "false", "Failed to list all routes for table $table! Has iproute been installed?";
  } else {
    if ($chkroute == 0) {
      return "false", "No route present for $route!", $chkroute;
    } elsif ($chkroute > 1) {
      return "false", "Too many routes present for $route!", $chkroute;
    } else {
      return "true", "Found route for $route!", 1;
    }
  }
}

# 2.03 delroute
# Function to delete a given route within a given table
sub delroute() {
  my ($route, $table, $err, $chkroute);
  if (!$_[0]) {
    return "false", "Given route argument was empty!";
  }
  if (!$_[1]) {
    return "false", "Given table argument was empty!";
  }
  $route = $_[0];
  $table = $_[1];
  chomp($route);
  chomp($table);

  ($chkroute, $err) = \&chkroute($route, $table);
  if ($chkroute eq "false") {
    return "false", $err;
  }
  `ip route del $route table $table 2>/dev/null`;
  if ($? != 0) {
    return "false", "Could not delete $route from table $table!";
  } else {
    return "true", "Successfully deleted route!";
  }
}

# 2.04 addroute
# Function to add a route to a given table
# Arguments:
#  $route - The route to be added (single IP address)
#  $gw - The gateway
#  $dev - Via which device
#  $table - into this table
sub addroute() {
  my ($route, $gw, $dev, $table, $err, $chkroute, $count);
  if (!$_[0]) {
    return "false", "Given route argument was empty!";
  }
  if (!$_[1]) {
    return "false", "Given gateway argument was empty!";
  }
  if (!$_[2]) {
    return "false", "Given device argument was empty!";
  }
  if (!$_[3]) {
    return "false", "Given table argument was empty!";
  }
  $route = $_[0];
  $gw = $_[1];
  $dev = $_[2];
  $table = $_[3];
  chomp($route);
  chomp($gw);
  chomp($dev);
  chomp($table);
  if ("$route" eq "") {
    return "false", "Cannot add empty route!";
  }
  if ("$gw" eq "") {
    return "false", "Cannot add route with empty gateway!";
  }
  if ("$dev" eq "") {
    return "false", "Cannot add route with empty device!";
  }
  if ("$table" eq "") {
    return "false", "Cannot add route to empty table!";
  }
  ($chkroute, $err, $count) = \&chkroute($route);
  if ($chkroute eq "false") {
    return "false", $err;
  }
  `ip route add $route via $gw dev $dev table $table 2>/dev/null`;
  if ($? != 0) {
    return "false", "Adding route $route to table $table with gateway $gw and device $dev failed!";
  } else {
    return "true", "Successfully added route!";
  }
}

#########################
# RULE FUNCTIONS
#########################

# 3.01 addrule
# Function to add an ip rule
sub addrule() {
  my ($if, $ifip, $chkif, $err, $count, $chkrule);
  if (!$_[0]) {
    return "false", "Given interface argument was empty!";
  }
  if (!$_[1]) {
    return "false", "Given IP address argument was empty!";
  }
  $if = $_[0];
  ($chkif, $err) = \&chkif($if);
  if ($chkif eq "false") {
    return "false", $err;
  }
  $ifip = $_[1];
  chomp($ifip);

  ($chkrule, $err, $count) = chkrule_by_ip($ifip);
  if ($chkrule eq "false") {
    if ($count == 0) {
      `ip rule add from $ifip table $if 2>/dev/null`;
      if ($? != 0) {
        return "false", "Adding ip rule failed!";
      } else {
        return "true", "Adding ip rule success!";
      }
    } else {
      return "false", $err;
    }
  } else {
    return "false", "Rule already present!";
  }
}

# 3.02 chkrule_by_ip
# Function to check for the existance of a rule given an IP address
sub chkrule_by_ip() {
  my ($rule, $chkrule);
  if (!$_[0]) {
    return "false", "Given rule argument was empty!";
  }
  $rule = $_[0];
  chomp($rule);
  if ("$rule" eq "") {
    return "false", "Cannot check empty rule!";
  }
  $chkrule = `ip rule list | grep $rule | wc -l 2>/dev/null`;
  chomp($chkrule);
  if ($? != 0) {
    return "false", "Failed to list all ip rules! Has iproute been installed?";
  } else {
    if ($chkrule == 0) {
      return "false", "No rule present for $rule!", 0;
    } elsif ($chkrule > 1) {
      return "false", "Too many rules present for $rule!", $chkrule;
    } else {
      return "true", "Found rule for $rule!", 1;
    }
  }
}

# 3.03 chkrule_by_if
# Function to check for the existance of a rule given an interface name
sub chkrule_by_if() {
  my ($if, $chkrule, $chkif, $err);
  if (!$_[0]) {
    return "false", "Given interface argument was empty!";
  }
  $if = $_[0];
  ($chkif, $err) = \&chkif($if);
  if ($chkif eq "false") {
    return "false", $err;
  }

  $chkrule = `ip rule list | grep '^.*lookup $if \$' | wc -l 2>/dev/null`;
  chomp($chkrule);
  if ($? != 0) {
    return "false", "Failed to list all ip rules! Has iproute been installed?", 0;
  } else {
    if ($chkrule == 0) {
      return "false", "No rule present for $if!", 0;
    } elsif ($chkrule > 1) {
      return "false", "Too many rules present for $if!", $chkrule;
    } else {
      return "true", "Found rule for $if!", 1;
    }
  }
}

# 3.04 chkrule
# Function to check for the existance of an ip rule 
# given both the IP address and interface name
sub chkrule() {
  my ($chkrule, $chkrule_if, $chkrule_ip, $ifip, $if, $chkif, $err, $count);
  if (!$_[0]) {
    return "false", "Given interface argument was empty!";
  }
  if (!$_[1]) {
    return "false", "Given IP address argument was empty!";
  }
  $if = $_[0];
  $ifip = $_[1];
  chomp($if);
  chomp($ifip);
  if ("$if" eq "") {
    return "false", "Cannot check rule for empty interface!";
  }
  if ("$ifip" eq "") {
    return "false", "Cannot check rule for empty interface IP address!";
  }
  ($chkif, $err) = \&chkif($if);
  if ("$chkif" eq "false") {
    return "false", $err;
  }
  ($chkrule_if, $err, $count) = \&chkrule_by_if($if);
  if ("$chkrule_if" eq "false") {
    return "false", $err, $count;
  } else {
    ($chkrule_ip, $err, $count) = \&chkrule_by_ip($ifip);
    if ("$chkrule_ip" eq "false") {
      return "false", $err;
    } else {
      return "true";
    }
  }
}

# 3.05 delrule_by_ip
# Function to delete an ip rule given an IP address
sub delrule_by_ip() {
  my ($rule, $err, $chkrule);
  if (!$_[0]) {
    return "false", "Given rule argument was empty!";
  }
  $rule = $_[0];
  chomp($rule);
  if ("$rule" eq "") {
    return "false", "Cannot delete rule for empty IP address!";
  }

  ($chkrule, $err) = \&chkrule_by_ip($rule);
  if ($chkrule eq "false") {
    return "false", $err;
  }
  `ip rule del from $rule 2>/dev/null`;
  if ($? != 0) {
    return "false", "Could not delete rule for $rule!";
  } else {
    return "true";
  }
}

# 3.06 delrule_by_if
# Function to delete an ip rule given an interface
sub delrule_by_if() {
  my ($if, $err, $chkrule);
  if (!$_[0]) {
    return "false", "Given interface argument was empty!";
  }
  $if = $_[0];
  chomp($if);
  if ("$if" eq "") {
    return "false", "Cannot delete rule for empty interface!";
  }

  ($chkrule, $err) = \&chkrule_by_if($if);
  if ($chkrule eq "false") {
    return "false", $err;
  }
  `ip rule del lookup $if 2>/dev/null`;
  if ($? != 0) {
    return "false", "Could not delete rule for $if!";
  } else {
    return "true";
  }
}

# 3.07 getallrules
# Function to get all ip rules
sub getallrules() {
  my(@rules);
  @rules = `ip rule list | grep -v main | grep -v default | grep -v all | awk '{print \$3}' 2>/dev/null`;
  if ($? != 0) {
    return "false", "Listing all ip rules failed! Has iproute been installed?";
  } else {
    return "true", "Retrieving all rules: OK!", @rules;
  }
}

#########################
# FIX FUNCTIONS
#########################

# 4.01 fix_rule
# Function to fix the rule of a sensor
sub fix_rule() {
  my ($chk_rule_if, $chk_rule_ip, $chk, $err, $if, $ifip, $rule_if_count, $rule_ip_count, $i);
  if (!$_[0]) {
    return "false", "Given IF rule check argument was empty!";
  }
  if (!$_[1]) {
    return "false", "Given IP rule check argument was empty!";
  }
  if (!$_[2]) {
    return "false", "Given interface argument was empty!";
  }
  if (!$_[3]) {
    return "false", "Given IP address argument was empty!";
  }
  if (!$_[4]) {
    return "false", "Given IF count argument was empty!";
  }
  if (!$_[5]) {
    return "false", "Given IP count argument was empty!";
  }
  $chk_rule_if = $_[0];
  $chk_rule_ip = $_[1];
  $if = $_[2];
  $ifip = $_[3];
  $rule_if_count = $_[4];
  $rule_ip_count = $_[5];
  chomp($chk_rule_if);
  chomp($chk_rule_ip);
  chomp($if);
  chomp($ifip);
  chomp($rule_if_count);
  chomp($rule_ip_count);
  if ($chk_rule_if eq "") {
    return "false", "Missing argument1!";
  }
  if ($chk_rule_ip eq "") {
    return "false", "Missing argument2!";
  }
  if ($if eq "") {
    return "false", "Missing interface name!";
  }
  if ($ifip eq "") {
    return "false", "Missing interface IP address!";
  }
  if ($rule_if_count eq "") {
    return "false", "Missing argument5!";
  }
  if ($rule_ip_count eq "") {
    return "false", "Missing argument6!";
  }

  if ($chk_rule_if eq "false" && $chk_rule_ip eq "false") {
    if ($rule_if_count > 0) {
      for ($i = 0; $i < $rule_if_count; $i++) {
        ($chk, $err) = \&delrule_by_if($if);
      }
    }
    if ($rule_ip_count > 0) {
      for ($i = 0; $i < $rule_ip_count; $i++) {
        ($chk, $err) = \&delrule_by_ip($ifip);
      }
    }
    if ($chk_if eq "true" && $chk_ifip eq "true") {
      ($chk, $err) = \&addrule($if, $ifip);
      return $chk, $err;
    }
    return "true", "No fix was needed!";
  } elsif ($chk_rule_if eq "false") {
    if ($chk_rule_ip eq "true") {
      ($chk, $err) = \&delrule_by_ip($ifip);
      return $chk, $err;
    }
    ($chk, $err) = \&addrule($if, $ifip);
    $bla = \&logmsg($chk, $err, "Adding rule for $if with $ifip!");
    return $chk, $err;
  } elsif ($chk_rule_ip eq "false") {
    if ($chk_rule_if eq "true") {
      ($chk, $err) = \&delrule_by_if($if);
    }
    ($chk, $err) = \&addrule($if, $ifip);
    $bla = \&logmsg($chk, $err, "Adding rule for $if with $ifip!");
    return $chk, $err;
  }
}

# 4.33 logsys
# Function to log messages to the syslog table
sub logsys() {
  my ($ts, $prefix, $msg, @row, $er, $sql, $sensorid, $dev);
  $prefix = $_[0];
  $level = $_[1];
  $msg = $_[2];
  $sensorid = $_[3];
  $dev = $_[4];
  chomp($prefix);
  chomp($msg);
  chomp($sensorid);
  chomp($dev);
  $ts = time();

  if ($_[5]) {
    $args = $_[5];
    chomp($args);
  } else {
    $args = "";
  }

  $sql = "INSERT INTO syslog (source, timestamp, error, args, level, sensorid, device) VALUES ";
  $sql .= " ('$prefix', '$ts', '$msg', '$args', '$level', '$sensorid', '$dev')";
  $er = $dbh->do($sql);
  return "true";
}

return "true";
