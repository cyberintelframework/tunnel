#!/bin/sh

################################
# Makeversion for IDS Server   #
# SURFnet IDS                  #
# Version 1.03.01              #
# 17-10-2006                   #
# Kees Trippelvitz             #
################################

####################
# Variables used
####################
updatesdir="/opt/surfnetids/updates"
runningdir="/opt/surfnetids/scriptkeys"

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
