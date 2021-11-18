#!/bin/bash

num=$(cat /proc/cpuinfo | grep "processor"| wc -l)
process=$[($num*2)/3]
path="spec/"
var=O2

BZIP=$path'bzip2_base.x86'.$var
MCF=$path'mcf_base.x86'.$var
LIBQ=$path'libquantum_base.x86'.$var
SJENG=$path'sjeng_base.x86'.$var
HMMER=$path'hmmer_base.x86'.$var
GOBMK=$path'gobmk_base.x86'.$var
GCC=$path'gcc_base.x86'.$var
H264=$path'h264ref_base.x86'.$var

echo "400"
cd $path"perlbench"
./run_$var.sh
cd ../../
echo "401" 
cp $BZIP $BZIP.stripped
strip $BZIP.stripped
time -p grin-lift $BZIP.stripped $BZIP.ll -multi-process-chains -process-nums=$process 2>$BZIP.log 1>/dev/null
rm $BZIP.stripped
echo "429"
cp $MCF $MCF.stripped
strip $MCF.stripped
time -p grin-lift $MCF.stripped $MCF.ll -multi-process-chains -process-nums=$process 2>$MCF.log 1>/dev/null
rm $MCF.stripped
echo "462"
cp $LIBQ $LIBQ.stripped
strip $LIBQ.stripped
time -p grin-lift $LIBQ.stripped $LIBQ.ll -multi-process-chains -process-nums=$process 2>$LIBQ.log 1>/dev/null
rm $LIBQ.stripped
echo "458"
cp $SJENG $SJENG.stripped
strip $SJENG.stripped
time -p grin-lift $SJENG.stripped $SJENG.ll -multi-process-chains -process-nums=$process -exe-args="--help" 2>$SJENG.log 1>/dev/null
rm $SJENG.stripped
echo "456"
cp $HMMER $HMMER.stripped
strip $HMMER.stripped
time -p grin-lift $HMMER.stripped $HMMER.ll -multi-process-chains -process-nums=$process 2>$HMMER.log 1>/dev/null
rm $HMMER.stripped
echo "445"
cp $GOBMK $GOBMK.stripped
strip $GOBMK.stripped
time -p grin-lift $GOBMK.stripped $GOBMK.ll -multi-process-chains -process-nums=$process -loop-nums=1154 -exe-args="--help" 2>$GOBMK.log 1>/dev/null
rm $GOBMK.stripped
echo "403"
cp $GCC $GCC.stripped
strip $GCC.stripped
time -p grin-lift $GCC.stripped $GCC.ll -multi-process-chains -process-nums=$process -dcph=1317 -exe-args="--help" 2>$GCC.log 1>/dev/null
rm $GCC.stripped
echo "464"
cp $H264 $H264.stripped
strip $H264.stripped
time -p grin-lift $H264.stripped $H264.ll -multi-process-chains -process-nums=$process -loop-nums=5 2>$H264.log 1>/dev/null
rm $H264.stripped

