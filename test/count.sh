#!/bin/bash

result="result/"
path1="coreutils_realworld/O2_lift/"

mkdir -p $result

cp $path1*.result $result

path2="spec/perlbench/"
cp $path2*.result $result

path3="spec/"
cp $path3*.result $result

python3 generate_result.py result/ -o ./result.csv

