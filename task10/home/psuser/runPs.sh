#!/bin/bash

echo "Powershell LP Loop -- Start"
sleep 30
cd /home/psuser/
while [ 1 ]
do
	if [ -f "/tmp/stop_ps" ]; then
		echo "Powershell LP -- Break"
		break
	fi	
	echo "Powershell LP -- Start"
	./powershell_lp 
	sleep 10
done

echo "Powershell LP Loop -- Exit"

