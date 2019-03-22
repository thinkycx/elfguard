#
# date: 2019-03-19
# author: thinkycx
#

import os
import sys
import pwn

FILENAME = ''




def usage():
	menu = '''
         __         ____                           __
   _____/ /_  ___  / / /___ ___  ______ __________/ /
  / ___/ __ \/ _ \/ / / __ `/ / / / __ `/ ___/ __  / 
 (__  ) / / /  __/ / / /_/ / /_/ / /_/ / /  / /_/ /  
/____/_/ /_/\___/_/_/\__, /\__,_/\__,_/_/   \__,_/   
                    /____/            
								[thinkycx@gmail.com]
								
	Usage:  python shellguard.py <FILENAME>
	
	'''
	print(menu)





if __name__ == '__main__':
	if len(sys.argv) < 2:
		usage()
	else:
		elf = pwn.ELF(sys.argv[1])
	os._exit(0)