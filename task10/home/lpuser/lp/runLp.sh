#!/bin/bash


echo "LP Loop -- Start"
sleep 30

cd /home/lpuser/lp/
while [ 1 ]
do
	if [ -f "/tmp/stop_lp" ]; then
		echo "LP -- Break"
		break
	fi	
	echo "LP -- Start"
	python3 lp.py
	sleep 10
done

echo "LP Loop -- Exit"

