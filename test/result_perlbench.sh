#!/bin/sh

echo "perlbench"
file1="spec/perlbench/perlbench_base.x86.O2"
file2="spec/perlbench/perlbench_base.x86.O3"
objdump $file1 -d 1>$file1.obj
python3 cmp_instruction.py $file1

objdump $file2 -d 1>$file2.obj
python3 cmp_instruction.py $file2
