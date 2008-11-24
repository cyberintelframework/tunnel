<?php

####################################
# SURFids 2.10                     #
# Changeset 001                    #
# 19-11-2008                       #
# Jan van Lith & Kees Trippelvitz  #
####################################

#####################
# Changelog:
# 001 Initial release
#####################

$config_handle = @fopen("/etc/surfnetids/surfnetids-tn.conf", "r");
if ($config_handle) {
  while (!feof($config_handle)) {
    $buffer = fgets($config_handle);
    eval($buffer);
  }
}

?>
