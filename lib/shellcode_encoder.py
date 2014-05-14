###############################################################
#               Shellcode Encoder
#
#       Copyright (C) 2014 random <random@pku.edu.cn>
#
###############################################################
#!/usr/bin/env python
from random import *
from struct import *
import sys 


#import external libs
import config
from asicc_shellcode_helper import *
from utils import *


########################################

RANDOMIZE_SHELLCODE = True

########################################


class ShellcodeEncoder(object):
	"""docstring for ShellcodeEncoder"""
	
	def __init__(self):
		super(ShellcodeEncoder, self).__init__()



	@staticmethod
	def XorEncode(shellcode):
		pass



	@staticmethod
	def AsiccEncode(shellcode,random=RANDOMIZE_SHELLCODE):

		asmcode = ''
		shellcode_size = len(shellcode)
		if shellcode_size <= 0:
			print('no shellcode!')
			exit(0)

		#PADDING Shellcode with 0x90 by 4 align
		if shellcode_size%4 > 0:
			padding = 4-(shellcode_size%4)
			shellcode += padding * '\x90'
			shellcode_size += padding

		byte_count = 0
		pre_value = 0
		shellcode = shellcode[::-1]
		for i in xrange(0, shellcode_size, 4):
			#by using big-endian '>I' , because shellcode has been reversed "shellcode[::-1]"
			value = unpack('>I',shellcode[i:i+4])[0]
			AsiccValueList = GetAsiccValues((0x100000000 + pre_value - value),random)
			
			size = len(AsiccValueList)
			if size == 0:
				print 'no data'
				exit(0)		

			for j in xrange(size):
				byte_count += 5
				asmcode += 'sub  eax, 0x%08x%c'%(AsiccValueList[j],IFS)

			asmcode += 'push eax%c'%(IFS)
			byte_count += 1
			pre_value = value

		# ZeroEAX contains 10 bytes at most
		# AddESP contains 19 bytes at most
		byte_count += 19 + 10
		total_size = byte_count + shellcode_size
		print('\n[!] make sure that the stack-based overflow vuln must have 0x%08x bytes space at least to save shellcode!'%total_size)
		raw_input('\n--continue--')
		asmcode = ZeroEAX() + asmcode			
		asmcode = AddESP(total_size) + asmcode	
		return asmcode


	@staticmethod
	def ReadRawShellcodeFromFile(binfile):
		shellcode = ''
		try:
			fd = open(binfile,'rb')
			shellcode = fd.read()
			fd.close()
		except Exception,e:
			print e
			exit(0)
		return shellcode


	@staticmethod
	def nasm_assemble(nasm_path, asmcode):
		"""
		Assemble ASM instructions using NASM
			- asmcode: input ASM instructions, multiple instructions are separated by ";" (String)
		Returns:
			- bin code (raw bytes)
		"""

		if not check_file_exist(nasm_path):
			return 

		mode = config.Option.get('mode')		#mode: 16 / 32 / 64
		if mode not in [16, 32, 64]:
			print('error mode')
			exit(0)

		asmcode = asmcode.strip('"').strip("'")
		asmcode = asmcode.replace(";", "\n")
		asmcode = ("BITS %d\n" % mode) + asmcode
		asmcode = asmcode.decode('string_escape')

		infile = 'shellcode_encoder.in'
		outfile = config.TMP_DIR + r'/' + 'shellcode_encoder.out'

		infd = tmpfile(config.TMP_DIR,infile,'w')
		infd.write(asmcode)
		infd.flush()
		infd.close()
		
		command = config.NASM_COMMAND_FORMAT % (nasm_path, outfile, infd.name)
		execute_command(command)
		
		outfd = open(outfile,'r')
		bincode = outfd.read()
		outfd.close()
		
		if bincode == None or len(bincode) == 0 :
			print "bad asmcode!!"
			return ''

		return bincode

	@staticmethod
	def out_format(language, ouput,ALIGN = 16):

		ret = ''

		def hexify(_str):
			return '\\x%02x' % (ord(_str))

		if language == 'bin':
				ret += ouput

		if language == 'c':
				ret += '\nchar shellcode[] = \\\n\"'
				for i in xrange(len(ouput)):
					ret += hexify(ouput[i])
					if  not (i+1) % ALIGN :
						ret += '\"\n\"'
				ret += '\";\n'

		if language == 'python':
				ret += '\nshellcode = \\\n\"'
				for i in xrange(len(ouput)):
					ret += hexify(ouput[i])
					if  not (i+1) % ALIGN :
						ret += '\" +\\\n\"'
				ret += '\"\n"'
		return ret

###############################################################################################


