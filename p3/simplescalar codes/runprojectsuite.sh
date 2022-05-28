#!/bin/bash
benchpairs=( "/home/software/simplesim/ss-benchmark/bzip2/bzip2_base.i386-m32-gcc42-nn /home/software/simplesim/ss-benchmark/bzip2/dryer.jpg" "/home/software/simplesim/ss-benchmark/mcf/mcf_base.i386-m32-gcc42-nn /home/software/simplesim/ss-benchmark/mcf/inp.in" "/home/software/simplesim/ss-benchmark/hmmer/hmmer_base.i386-m32-gcc42-nn /home/software/simplesim/ss-benchmark/hmmer/bombesin.hmm" "/home/software/simplesim/ss-benchmark/sjeng/sjeng_base.i386-m32-gcc42-nn /home/software/simplesim/ss-benchmark/sjeng/test.txt" "/home/software/simplesim/ss-benchmark/milc/milc_base.i386-m32-gcc42-nn < /home/software/simplesim/ss-benchmark/milc/su3imp.in")

width=( "1" "2" "4" "8" )
fetchspeed=( "1" "2" )
scheduling=( "-issue:inorder true -issue:wrongpath false" "-issue:inorder false -issue:wrongpath true" )
ruusize=( "4" "8" "16" "32" "64" "128" )
lsqsize=( "4" "8" "16" "32" )
memport=( "1" "2" )
dl1sets=( "32" "64" "128" "256" "512" "1024" "2048" "4096" "8192" )
dl1assoc=( "1" "2" "4" )
il1sets=( "32" "64" "128" "256" "512" "1024" "2048" "4096" "8192" )
il1assoc=( "1" "2" "4" )
ul2sets=( "256" "512" "1024" "2048" "4096" "8192" "16384" "32768" "65536" "131072" )
ul2block=( "16" "32" "64" "128" )
ul2assoc=( "1" "2" "4" "8" "16" ) 
tlbsets=( "4" "8" "16" "32" "64" )
dl1lat=( "1" "2" "3" "4" "5" "6" "7" )
il1lat=( "1" "2" "3" "4" "5" "6" "7" )
ul2lat=( "5" "6" "7" "8" "9" "10" "11" "12" "13" )
branchsettings=( "-bpred perfect" "-bpred nottaken" "-bpred bimod -bpred:bimod 2048" "-bpred 2lev -bpred:2lev 1 1024 8 0" "-bpred 2lev -bpred:2lev 4 256 8 0" "-bpred comb -bpred:comb 1024" )
l1block=( "8" "16" "32" "64" ) 

for benchnum in $(seq 0 $((${#benchpairs[*]} - 1))) ; do
    eval /home/software/simplescalar/x86_64/bin/sim-outorder -fastfwd 5000000 -max:inst 100000 -fetch:ifqsize ${width[$1]} -fetch:speed ${fetchspeed[$2]} -fetch:mplat 3 -decode:width ${width[$1]} -issue:width ${width[$1]} ${scheduling[$3]} -ruu:size ${ruusize[$4]} -lsq:size ${lsqsize[$5]} -res:ialu ${width[$1]} -res:imult ${width[$1]} -res:memport ${memport[$6]} -res:fpalu ${width[$1]} -res:fpmult ${width[$1]} -cache:dl1 dl1:${dl1sets[$7]}:${l1block[$1]}:${dl1assoc[$8]}:l -cache:il1 il1:${il1sets[$9]}:${l1block[$1]}:${il1assoc[${10}]}:l -cache:il2 dl2 -cache:dl2 ul2:${ul2sets[${11}]}:${ul2block[${12}]}:${ul2assoc[${13}]}:l -tlb:itlb itlb:${tlbsets[${14}]}:4096:4:l -tlb:dtlb dtlb:${tlbsets[${14}]}:4096:4:l -cache:dl1lat ${dl1lat[${15}]} -cache:il1lat ${il1lat[${16}]} -cache:dl2lat ${ul2lat[${17}]} -mem:lat 51 7 -mem:width 8 -tlb:lat 30 ${branchsettings[${18}]} -redir:sim rawProjectOutputData/"$benchnum"."${1}"."${2}"."${3}"."${4}"."${5}"."${6}"."${7}"."${8}"."${9}"."${10}"."${11}"."${12}"."${13}"."${14}"."${15}"."${16}"."${17}"."${18}".simout ${benchpairs[$benchnum]}
done

touch rawProjectOutputData/DONE."${1}"."${2}"."${3}"."${4}"."${5}"."${6}"."${7}"."${8}"."${9}"."${10}"."${11}"."${12}"."${13}"."${14}"."${15}"."${16}"."${17}"."${18}".DONE