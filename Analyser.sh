#!/bin/bash

# Get a choice from the user 

	echo "Please enter which one do you wanna scan: hdd or mem" 
	read -p "Please enter your answer: " ANSWER
if [ "$ANSWER" == mem ] 
then 
function MEM ()
{
	read -p "Please enter the file you want to investigate: " file 
	echo -e "\e[5m\e[41m  [*] Analyzing memory file , $file , It may take some time..     \e[0m" 
	
echo
	mkdir -p memory/vol
	
# Searching for profile .. 
	./vol -f $file imageinfo 2>/dev/null > memory/vol/profile

	PRO=$(cat memory/vol/profile | grep -i "Suggested Profile" | awk '{print $4}' | awk -F ',' '{print $1}')

# Analyzing the memory using Volatility ..
# Investigating Process & Dlls... 
mkdir -p memory/vol/Process_Dlls
PDLL='pslist pstree psscan psdispscan dlllist dlldump handles getsids cmdscan consoles privs envars verinfo enumfunc'

for i in $PDLL
do
./vol -f $file --profile=$PRO $i 2>/dev/null >> memory/vol/Process_Dlls/$i.txt
done

# Investigating the Process Memory ... 
mkdir -p memory/vol/Process_Memory
PRCMEM='memmap memdump procdump vadinfo vadwalk vadtree vaddump evtlogs iehistory'

for i in $PRCMEM
do
./vol -f $file --profile=$PRO $i 2>/dev/null >> memory/vol/Process_Memory/$i.txt
done	

# Investigating the Kernel Memory and Objects .. 
mkdir -p memory/vol/KernelMemory_Objects
KERMEMOB='modules modscan moddump ssdt driverscan filescan mutantscan symlinkscan thrdscan dumpfiles unloadedmodules'

for i in $KERMEMOB
do
./vol -f $file --profile=$PRO $i 2>/dev/null >> memory/vol/KernelMemory_Objects/$i.txt
done	

# Investigating Networking .. 
mkdir -p memory/vol/Networking
NET='connections connscan sockets sockscan netscan'

for i in $NET
do
./vol -f $file --profile=$PRO $i 2>/dev/null >> memory/vol/Networking/$i.txt
done	

# Investigating Registry ..
mkdir -p memory/vol/Registry
REG='hivescan hivelist printkey hivedump hashdump lsadump userassist shellbags shimcache getservicesids dumpregistry'

for i in $REG
do
./vol -f $file --profile=$PRO $i 2>/dev/null >> memory/vol/Registry/$i.txt  	
done	

# Investigating Crash Dumps, Hibernation, and Conversion ...
mkdir -p memory/vol/CrashDumps_Hibernation_Conversion
CDHC='crashinfo hibinfo imagecopy raw2dmp vboxinfo vmwareinfo hpakinfo hpakextract'

for i in $CDHC
do
./vol -f $file --profile=$PRO $i 2>/dev/null >> memory/vol/CrashDumps_Hibernation_Conversion/$i.txt
done	

# Investigating File System ...
mkdir -p memory/vol/File_system
SYS='mbrparser mftparser' 

for i in $SYS
do
./vol -f $file --profile=$PRO $i 2>/dev/null >> memory/vol/File_system/$i.txt
done	

# Investigating Miscellaneous ...  
mkdir -p memory/vol/Miscellaneous
MSCL='strings bioskbd patcher pagecheck timeliner'

for i in $MSCL
do
./vol -f $file --profile=$PRO $i 2>/dev/null >> memory/vol/Miscellaneous/$i.txt
done

# Analyzing  the memory using Binwalk 

# binwalk -e $file > memory_$file/binwalk_$file 2>/dev/null

# Analyzing  the memory using foremost 

foremost -i $file -t all -o memory/foremost 

# Analyzing  the memory using Bulk_extractor 

bulk_extractor $file -o  &>/dev/null memory/bulk

# Analyzing  the memory using strings 
touch memory/strings 
strings $file >> memory/strings 

echo	
	echo -e "\033[1;31m [+] Done"
echo	
	echo -e "\033[1;31m  Start analyzing results.." 
} 
MEM

else

function HDD ()
{
	read -p "Please enter a hdd file : " FILE
	
	 echo -e "\e[5m\e[44m  [*] Analyzing hdd file , $FILE , It may take some time..       \e[0m" 
	
mkdir ./hdd
# Analyzing hdd file using strings .. 
	strings $FILE  &>/dev/null >> ./hdd/strings 
	
# Analyzing hdd file using bulk .. 	
	bulk_extractor $FILE -o &>/dev/null ./hdd/bulk 
	
# Analyzing hdd file using binwalk .. 	
	binwalk -e $FILE 2>/dev/null > ./hdd/binwalk 
	
# Analyzing hdd file using foremost .. 	
	foremost -i $FILE -t all -o &>/dev/null ./hdd/foremost
echo
	echo -e "\033[1;31m [+] Done"
echo
	echo -e "\033[1;31m  Start analyzing results.." 
}
HDD

fi 

# Display general analysis statistics .. 
# Check if mem or hdd , then analyze --> 

if [ "$ANSWER" == mem ] 
then 

function LOG1 ()
{
	
# Show analysis results ..
echo 
	echo -e "\e[3m\e[44m   Statistics for memory analysis:    \e[0m" 
echo
	
	cd ~/Desktop/memory/vol
	echo -e "\e[3m\e[41m  Volatility results:        \e[0m" 
	
# Check for empty objects ---> If empty- delete ..
	find . -size 0 -delete
echo
	echo "Profiles that were found- $(cat profile | grep -i profile | awk '{print $4,$5}')"
echo
	echo " Found $(du -a | cut -d/ -f2 | sort | uniq -c | sort -nr | wc -l) directories: " 
echo
	echo " $(du -a | cut -d/ -f2 | sort | uniq -c | sort -nr) " 
echo
	echo -e "The directories content:"
	ls -lha *
echo	
	cd ~/Desktop/memory/bulk
# Check for empty objects ---> If empty- delete ..
	find . -size 0 -delete
	echo -e "\e[3m\e[41m  Bulk_extractor results:    \e[0m" 
echo
	
PCAP=$(ls -l | grep -i pcap | wc -l)
MAIL=$(ls -l | grep -i email | wc -l)
DOMAIN=$(ls -l | grep -i domain | wc -l)
XML=$(ls -l | grep -i xml | wc -l)
ALERT=$(ls -l | grep -i alert | wc -l)
URL=$(ls -l | grep -i url | wc -l)
TCP=$(ls -l | grep -i tcp | wc -l)
IP=$(ls -l | grep -i ip | wc -l)
RFC=$(ls -l | grep -i rfc | wc -l) 
WIN=$(ls -l | grep -i win | wc -l) 
DIR=$(find -maxdepth 1 -mindepth 1 -type d | wc -l)

	echo "Found $PCAP pcap files"  
	echo "Found $MAIL email files"  
	echo "Found $DOMAIN domain files"  
	echo "Found $XML xml files"
	echo "Found $ALERT alerts files"    
	echo "Found $URL url files"  
	echo "Found $TCP tcp files"  
	echo "Found $IP ip files"  
	echo "Found $RFC rfc files"  
	echo "Found $WIN win files"  
echo
	echo "Found $DIR folders: "   
	find -maxdepth 1 -mindepth 1 -type d 
echo
	echo -e "\e[3m\e[41m  Foremost results:      \e[0m" 
echo	
cd ~/Desktop/memory/foremost
# Check for empty objects ---> If empty- delete ..
	find . -size 0 -delete
	echo "Found $(find -maxdepth 1 -mindepth 1 -type f | wc -l) files: " 
    echo "$(find -maxdepth 1 -mindepth 1 -type f)" 
echo
    echo "Found $(find -maxdepth 1 -mindepth 1 -type d | wc -l) directories: " 
	find -maxdepth 1 -mindepth 1 -type d | cut -d/ -f2
echo
	
cd ~/Desktop/memory
echo
	echo -e "\e[3m\e[41m   Strings results:     \e[0m" 
echo	
	echo "Found $(cat strings | sort | uniq | wc -l) lines in strings"	
echo	
	echo -e "\033[1;31m [!!] Done analysing statistics for memory"
}

LOG1

	else	

function LOG2 ()
{
	
# Show analysis results .. 
echo
	echo -e "\e[3m\e[42m   Statistics for HDD analysis:       \e[0m" 
echo

cd ~/Desktop/hdd
	echo -e '\033[32m Binwalk results:  \033[0m'
echo
	echo "Found $(cat binwalk | sort | uniq | wc -l) files in binwalk:" 
echo
	echo "$(cat binwalk | grep -i zip | sort | uniq | wc -l) of them are zip files" 
	echo "$(cat binwalk | grep -i xml | sort | uniq | wc -l) of them are xml files" 
	echo "$(cat binwalk | grep -i image | sort | uniq | wc -l) of them are images" 
	echo "$(cat binwalk | grep -i png | sort | uniq | wc -l) of them are png" 
echo
	echo -e '\033[32m Strings results:   \033[0m'
echo	
	echo "Found $(cat strings | sort | uniq | wc -l) lines in strings"		

echo	
	echo -e '\033[32m  Foremost results:    \033[0m'
echo	
cd ~/Desktop/hdd/foremost
# Check for empty objects ---> If empty- delete ..
	find . -size 0 -delete
	echo "Found $(find -maxdepth 1 -mindepth 1 -type f | wc -l) files: " 
    echo "$(find -maxdepth 1 -mindepth 1 -type f)" 
echo
    echo "Found $(find -maxdepth 1 -mindepth 1 -type d | wc -l) directories: " 
	find -maxdepth 1 -mindepth 1 -type d | cut -d/ -f2
echo
	
	cd ~/Desktop/hdd/bulk
# Check for empty objects ---> If empty- delete ..
	find . -size 0 -delete
	echo -e '\033[32m  Bulk_extractor results:    \033[0m'
echo
	
PCAP=$(ls -l | grep -i pcap | wc -l)
MAIL=$(ls -l | grep -i email | wc -l)
DOMAIN=$(ls -l | grep -i domain | wc -l)
XML=$(ls -l | grep -i xml | wc -l)
ALERT=$(ls -l | grep -i alert | wc -l)
URL=$(ls -l | grep -i url | wc -l)
TCP=$(ls -l | grep -i tcp | wc -l)
IP=$(ls -l | grep -i ip | wc -l)
RFC=$(ls -l | grep -i rfc | wc -l) 
WIN=$(ls -l | grep -i win | wc -l) 
DIR=$(find -maxdepth 1 -mindepth 1 -type d | wc -l)

	echo "Found $PCAP pcap files"  
	echo "Found $MAIL email files"  
	echo "Found $DOMAIN domain files"  
	echo "Found $XML xml files"
	echo "Found $ALERT alerts files"    
	echo "Found $URL url files"  
	echo "Found $TCP tcp files"  
	echo "Found $IP ip files"  
	echo "Found $RFC rfc files"  
	echo "Found $WIN win files"  
echo
	echo "Found $DIR folders: "   
	find -maxdepth 1 -mindepth 1 -type d
	
	echo
	echo " Found $(du -a | cut -d/ -f2 | sort | uniq -c | sort -nr | wc -l) directories: " 
	echo
	echo " $(du -a | cut -d/ -f2 | sort | uniq -c | sort -nr) " 
	echo
		
	echo -e "\033[1;31m [!!] Done analysing statistics for hdd"
	
}

LOG2

fi 		