#!/bin/sh

################################
# Makeversion for IDS Server   #
# SURFnet IDS                  #
# Version 1.02.01              #
# 15-02-2006                   #
# Kees Trippelvitz             #
################################

####################
# Variables used
####################
updatesdir="/home/surfids/trunk/updates"
runningdir="/home/surfids/trunk/scriptkeys"

####################
# Main script
####################
rm -f $updatesdir/server_version.txt

for file in `grep -I Version $updatesdir/* | grep -v ".sig" | awk '{print $1}' | cut -d":" -f1`
do
  version=`grep -I Version $updatesdir/* | grep "^${file}:" | awk '{print $3}'`
  file=`echo $file | awk -F / '{print $NF}'`
  echo "$file:$version"
  echo "${file}:${version}" >> $updatesdir/server_version.txt
done

echo -e "Creation of $updatesdir/server_version.txt done."
echo -e "Please check if the creation was succesful."
