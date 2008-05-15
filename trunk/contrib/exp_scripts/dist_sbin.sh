#/bin/sh

if [ -f scen$1 ]
then
  SCENE=$1
  shift
else
  SCENE=4
fi

./all.sh $SCENE -Ivm scp -i id_rsa $@ vm:/usr/sbin
