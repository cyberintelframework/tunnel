#!/bin/sh

#########################################
# Sign all updates for the IDS Server   #
# SURFnet IDS                           #
# Version 1.03.01                       #
# 17-10-2006                            #
# Kees Trippelvitz                      #
#########################################

####################
# Variables used
####################
udir="/opt/surfnetids/updates"
basedir="/opt/surfnetids/scriptkeys"

####################
# Main script
####################
rm $udir/*.sig 2>/dev/null
$basedir/makeversion.sh
$basedir/sign_file.sh $udir $basedir client.conf
$basedir/sign_file.sh $udir $basedir idsmenu
$basedir/sign_file.sh $udir $basedir start_bridge
$basedir/sign_file.sh $udir $basedir startclient
$basedir/sign_file.sh $udir $basedir stopclient
$basedir/sign_file.sh $udir $basedir update
$basedir/sign_file.sh $udir $basedir update_remove
$basedir/sign_file.sh $udir $basedir wgetrc
$basedir/sign_file.sh $udir $basedir scripts.crt
$basedir/sign_file.sh $udir $basedir scripts.conf
$basedir/sign_file.sh $udir $basedir network_config
