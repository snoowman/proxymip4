#/bin/sh
echo -n ping $1\ 
ping -c 1 -w 1 $1 &> /dev/null && echo online || echo offline
