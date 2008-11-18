<?php

####################################
# SURFids 2.00.04                  #
# Changeset 001                    #
# 14-09-2007                       #
# Jan van Lith & Kees Trippelvitz  #
####################################

#####################
# Changelog:
# 001 version 2.00
#####################

$config_handle = @fopen("/etc/surfnetids/surfnetids-tn.conf", "r");
if ($config_handle) {
  while (!feof($config_handle)) {
    $buffer = fgets($config_handle);
    eval($buffer);
  }
}

?>
