#!/bin/sh
opath="coreutils_realworld/O2/"
path="coreutils_realworld/O2_lift/"

files=$(ls $opath)
for str in $files
do

	filename=${str##*/}
	echo $filename
	objdump $opath$filename -d 1>$path$filename.O2.obj
	python3 cmp_instruction.py $path$filename.O2
done
