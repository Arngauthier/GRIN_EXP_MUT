#!/bin/bash
num=$(cat /proc/cpuinfo | grep "processor"| wc -l)
process=$[($num*2)/3]  
var=O2

time -p grin-lift perlbench_base.x86.$var perlbench_base.x86.$var.ll -multi-process-chains -process-nums=$process -exe-args="-I. -I./lib attrs.pl" 2>perlbench_base.x86.$var.log 1>/dev/null
echo " "
