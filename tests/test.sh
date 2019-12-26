#!/bin/bash
# author: thinkycx
# date: 20191225

# Utils
echoColor(){
    # wrapper for echo to print green text
    # more info: https://blog.csdn.net/David_Dai_1108/article/details/70478826
    # Usage:
    #      echoColor $green "content" 
    green="\033[32m"
    red="\033[0;31m"
    lightcygan="\033[1;36m"
    colorend="\033[0m"
    echo -e $1$2$colorend
}

runCommand(){
    # echoColor $red "Test case:" 
    echoColor $red "$1" 
    bash -c "$1" 1>/dev/null
}

# quit if the following commands has errors
set -e

echoColor $red "Start test..."
runCommand "python ../elfguard.py -h"

echoColor $green "test storage module"
runCommand "python ../elfguard.py -f ../samples/heapcreator -st expand"
runCommand "python ../elfguard.py -f ../samples/heapcreator -st add"
runCommand "python ../elfguard.py -f ../samples/heapcreator -st eh_frame "

echoColor $green "test shellcode "
runCommand "python ../elfguard.py -f ../samples/heapcreator -st expand -sc reverseshell --ip 127.0.0.1 --port 7777"
runCommand "python ../elfguard.py -f ../samples/heapcreator -st expand -sc seccomp"

echoColor $green "test controller module"
runCommand "python ../elfguard.py -f ../samples/heapcreator -st expand -c plthook"
runCommand "python ../elfguard.py -f ../samples/heapcreator -st expand -c plthook -m func_plt_number -mp 0"
runCommand "python ../elfguard.py -f ../samples/heapcreator -st expand -c plthook -m func_name -mf malloc"

runCommand "python ../elfguard.py -f ../samples/heapcreator -st expand -c entryhook" 

echoColor $green "Congratulations! All test cases have been passed!"