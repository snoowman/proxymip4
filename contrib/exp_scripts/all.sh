#/bin/sh
SCENE=$1

if [ ! -f scen$1 ]
then
  SCENE=4
else
  SCENE=$1
  shift
fi

cat scen$SCENE | xargs -L1 $@
