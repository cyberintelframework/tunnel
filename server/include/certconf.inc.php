<?php

####################################
# SURFnet IDS                      #
# Version 2.00.01                  #
# 14-09-2007                       #
# Jan van Lith & Kees Trippelvitz  #
####################################

#####################
# Changelog:
# 2.00.01 version 2.00
# 1.04.01 Released as 1.04.01
# 1.03.01 Released as part of the 1.03 package
# 1.02.01 Initial release
#####################

$config_handle = @fopen("/etc/surfnetids/surfnetids-tn.conf", "r");
if ($config_handle) {
  while (!feof($config_handle)) {
    $buffer = fgets($config_handle);
    eval($buffer);
  }
}

?>
