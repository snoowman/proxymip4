#!/bin/sh
ID=`xm list | grep mnode | awk '{print $2}'`
if [ -n $ID ]
then
  brctl delif xenbr1 vif$ID.0 || brctl delif xenbr3 vif$ID.0
  brctl addif xenbr2 vif$ID.0
  ssh pmagent1 /usr/sbin/pmip4-pma -m 192.168.101.3 -h 192.168.101.1 -g 192.168.101.1 -c 192.168.100.2 -i eth1 -s 1000 -r
fi
