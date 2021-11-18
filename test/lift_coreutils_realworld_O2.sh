#!/bin/bash

n=$(cat /proc/cpuinfo | grep "processor"| wc -l)
process=$(expr $n \* 2)
processes=$(expr $process \/ 3)

rm -rf coreutils_realworld/O2_lift
mkdir coreutils_realworld/O2_lift
O2_path="coreutils_realworld/O2/"
result_path="coreutils_realworld/O2_lift/"
files=$(ls $O2_path)
for filename in $files
do
{
	echo $filename
	cp $O2_path$filename $result_path$filename.O2
	strip $result_path$filename.O2
	time -p grin-lift $result_path$filename.O2 $result_path$filename.O2.ll -multi-process-chains -process-nums=$processes -exe-args="-h" 1>/dev/null 2>$result_path$filename.O2.log
}
done
