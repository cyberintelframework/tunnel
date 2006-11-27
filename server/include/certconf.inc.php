<?php
####################################
# SURFnet IDS                      #
# Version 1.02.01                  #
# 03-05-2006                       #
# Jan van Lith & Kees Trippelvitz  #
####################################

  $config_handle = @fopen("/etc/surfnetids/surfnetids-tn.conf", "r");
  if ($config_handle) {
    while (!feof($config_handle)) {
      $buffer = fgets($config_handle);
      eval($buffer);
    }
  }
?>
