#/bin/sh
killall ssh
./all.sh $1 -Ivm ssh -fN -i id_rsa vm
