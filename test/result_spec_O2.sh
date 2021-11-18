#!/bin/sh

path="spec/"

files=$(ls $path*.O2)

echo "perlbench"
file1="spec/perlbench/perlbench_base.x86.O2"
objdump $file1 -d 1>$file1.obj
python3 cmp_instruction.py $file1

for str in $files
do

	filename=${str##*/}
	echo $filename
	objdump $path$filename -d 1>$path$filename.obj
	python3 cmp_instruction.py $path$filename
done

