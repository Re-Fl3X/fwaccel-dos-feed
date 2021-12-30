#!/bin/bash

#===========================================================================
=========================
# Global variables
#===========================================================================
=========================
if [[ -e /etc/profile.d/CP.sh ]]; then
source /etc/profile.d/CP.sh
fi

if [[ -e /etc/profile.d/vsenv.sh ]]; then source /etc/profile.d/vsenv.sh fi

#===========================================================================
=========================
# Variables
#===========================================================================
=========================
#Set current directory as logpath
LOGFILE="./fwaccel-dos-feed.log"

#Virtual System the Deny List has to be added to
VSENV=1

#IP Feed from Greynoise which is used for this script
GREYNOISE_URL=https://gist.githubusercontent.com/gnremy/c546c7911d5f876f263309d7161a7217/raw/fd1642bd37c90ea3f11adecc0a7ac86998a0e439/CVE-2021-44228_IPs.csv

#===========================================================================
=========================
# Environment checks
#===========================================================================
=========================
ISVSX=`$CPDIR/bin/cpprod_util FwIsVSX`
if [[ ! $ISVSX -eq 1 ]]; then
    printf "This script is only supported on VSX\n"
    exit 1
fi

CLCHK=$(clish -c exit)
if [[ ! -z "$CLCHK" ]]; then
    printf "Clish returns error: $CLCHK\n Please resolve this before executing the script again.\n\n" >> $LOGFILE
    exit 1
fi

#Needs to be fixed as sk112454 states it's supported from R80.20 and higher #CPVER=$(clish -c "show version product" | sed 's/.*R//' | awk -F. '{print "R" $1 "." $2}') #if [[ $CPVER != *"R8"* ]]; then
#    printf "This script is only supported on VSX with R80.10 and higher\n"
#    exit 1
#fi

#===========================================================================
=========================
# bash script
#===========================================================================
=========================


# Fetch IP list
curl_cli -skL $GREYNOISE_URL --output greynoise-ip-list.tmp res=$?
if test "$res" != "0"; then
 printf "The curl_cli command failed with: $res"
 printf "The curl_cli command failed with: $res" >> $LOGFILE exit 1 fi

cat greynoise-ip-list.tmp | awk -F , '{print $1}' > greynoise-ip-list.txt

if [[ -e greynoise-ip-list-old.txt ]]; then  # sha256sum on both old and new file to determine something has to be done  OLDSUM=$(sha256sum greynoise-ip-list-old.txt | awk '{print $1}')  NEWSUM=$(sha256sum greynoise-ip-list.txt | awk '{print $1}')

 # log sha256sum to file
 printf "Old SHA256 Hash $OLDSUM \n New SHA256 Hash $NEWSUM \n\n" >> $LOGFILE else  # Old file does not exist, assume script runs for the first time  # sha256sum on both old and new file to determine something has to be done  touch greynoise-ip-list-old.txt  OLDSUM=$(sha256sum greynoise-ip-list-old.txt | awk '{print $1}')  NEWSUM=$(sha256sum greynoise-ip-list.txt | awk '{print $1}')

 # log sha256sum to file
 printf "Script runs for the first time\n SHA256 Hash $NEWSUM \n\n" >> $LOGFILE fi

#Scratch version of IP Format Check(er)
#ip="1.2.3.4"
#if [[ "$ip" =~
^(([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))\.){3}([1-9]?[0-9]|1[0-9][0-
9]|2([0-4][0-9]|5[0-5]))$ ]]; then
#  echo "success"
#else
#  echo "fail"
#fi
echo NEW: $NEWSUM
echo OLD: $OLDSUM

#When $NEWSUM sum differs from $OLDSUM there is an update if [[ $NEWSUM != $OLDSUM ]] then  #cp -rlf greynoise-ip-list.txt greynoise-ip-list-old.txt  vsenv $VSENV > /dev/null 2>&1  fwaccel dos deny -l greynoise-ip-list.txt  printf "List added to DOS/Rate Limiting Deny List of VS$VSENV.\n"
 printf "List added to DOS/Rate Limiting Deny List of VS$VSENV.\n" >> $LOGFILE  printf "$0 completed at `date` \n" >> $LOGFILE else  printf "Nothing to do here. \n"
 printf "Nothing to do\n" >> $LOGFILE
 printf "$0 completed at `date` \n" >> $LOGFILE fi

exit 0
