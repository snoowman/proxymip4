#!/bin/sh
ID=`xm list | grep mnode | awk '{print $2}'`
if [ -n $ID ]
then
  brctl delif xenbr3 vif$ID.0
  brctl addif xenbr1 vif$ID.0

  ssh pmagent2 /usr/sbin/pmip4-pma -m 192.168.101.3 -h 192.168.101.1 -c 192.168.100.3 -i eth1 -l 0 -s 1000
fi
