#!/bin/sh
./daemon.sh stop

cp /home/quinn/proxymip4/sa /tmp/pmip4-sa
cp /home/quinn/proxymip4/ha /tmp/pmip4-ha
cp /home/quinn/proxymip4/pma /tmp/pmip4-pma

./dist_sbin.sh $1 -q /tmp/pmip4-*

./daemon.sh start
./daemon_log.sh $1
