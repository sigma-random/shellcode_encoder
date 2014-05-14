###############################################################
#               Shellcode Encoder
#
#       Copyright (C) 2014 random <random@pku.edu.cn>
#
###############################################################


from random import *
from struct import *

############################################

IFS = '\n'

ASICC_RANGE = {'min':0x21,'max':0x7E}


ASICC_OPCODE_MAP = {
	0x55:'push ebp'

}


############################################


def ZeroEAX():
	asmcode = ''
	val  = 0x00000000
	_val = 0x00000000
	while True:
		val  = RandomAsiccDWORD()
		_val = GetNotDwordInAsicc(val)
		if _val > 0:
			break
	asmcode += 'and  eax, 0x%08x%cand  eax, 0x%08x%c' % (val,IFS,_val,IFS)
	#print asmcode
	return asmcode


def GetNotDwordInAsicc(val): 
	max = 0xFFFFFFFF^val
	ret = 0x00000000
	for i in xrange(4):
		byte = (max>>(i*8))&0xFF
		#print 'byte[%d]=0x%02x' %(i,byte)
		if byte < ASICC_RANGE['min']:
			return 0x00000000
		elif ASICC_RANGE['min'] <= byte <= ASICC_RANGE['max']:
			ret += byte<<(i*8)
		elif byte > ASICC_RANGE['max']:
			for a in xrange(ASICC_RANGE['min'],ASICC_RANGE['max']+2):
				if ASICC_RANGE['min'] <= (a&byte) <= ASICC_RANGE['max']:
					#print '############found a=0x%02x###########'%a
				 	ret += a<<(i*8)
				 	break
				if a > ASICC_RANGE['max']:
					#print 'not found'
					return 0x00000000
		
	return ret

	

def AddESP(val):

	asmcode = 'push esp%cpop  eax%c'%(IFS,IFS)
	val = 2**32 - val
	#print '0x%08x' % val
	AsiccValueList =  GetAsiccValues(val)
	size = len(AsiccValueList)
	if size == 0:
		print 'no data'
		exit(0)
	for i in xrange(size):
		asmcode += 'sub  eax, 0x%08x%c'%(AsiccValueList[i],IFS)
	asmcode += 'push eax%cpop  esp%c'%(IFS,IFS)
	#print asmcode
	return asmcode


def GetAsiccValues(val,random=True):

	AsiccValueList = []
	#print '[*] 0x%08x' % val
	count = GetSeparateCount(val)
	#print('[*] count = %d'%count)
	AsiccValueList = SeparateIntoAsiccValue(val,count,4,random)
	if len(AsiccValueList) == 0:
		print('[!] Fail to Separate [0x%08x] into AsiccValues !'%val)
		exit(0)
	
	#PrintAsciiValueResult(AsiccValueList)

	return AsiccValueList


def SeparateIntoAsiccValue(val,count,maxcount=3,random=True):
	
	AsiccValueList = []
	borrow = 0

	if count == 1 and ASICC_RANGE['min']<= val<=ASICC_RANGE['max']:
		return [val]

	if count > maxcount:
		return []

	for i in xrange(count):
		AsiccValueList.append(0x00000000)

	for i in xrange(4):
		byte = (val>>i*8)&0xFF
		if borrow == 1:
			byte = byte - 1
			borrow = 0
		if byte < ASICC_RANGE['min'] * count:
			byte = byte + 0x100
			borrow = 1

		value = (byte / count)
		if not CheckIsAsiccByte(value):
			#print('[!] find bad byte1 value:0x%02x'%value)
			#print('[!] turn to separate %d AsiccValues!!'%(count+1))
			return SeparateIntoAsiccValue(val,count+1,maxcount,random)	

		mark = 0
		for j in xrange(count-1):
			mark ^= 1
			new_value = value
			if random == True:
				new_value = RandomizeValue(value,mark)
			AsiccValueList[j] = (AsiccValueList[j] + (new_value<<(i*8)))&0xFFFFFFFF

	for i in xrange(count-1):
		AsiccValueList[count-1] += AsiccValueList[i]
	AsiccValueList[count-1] = (val - AsiccValueList[count-1])&0xFFFFFFFF
	
	for i in xrange(4):
		tmp = AsiccValueList[count-1]>>(i*8)&0xFF
		if not CheckIsAsiccByte(tmp):
			print('[!] find bad byte1 value:0x%02x'%tmp)
			print('[!] turn to separate %d AsiccValues!!'%(count+1))
			return SeparateIntoAsiccValue(val,count+1,maxcount,random)

	return AsiccValueList



def GetSeparateCount(val):
	maxcount = 0
	byte = 0x00
	for i in xrange(4):
		count = 0
		byte = (val>>i*8)&0xFF
		if ASICC_RANGE['min']<= byte <= ASICC_RANGE['max']:
			count = 1
		elif byte<ASICC_RANGE['min']:
			count = (byte+0x100) / ASICC_RANGE['max']
			if (byte+0x100) % ASICC_RANGE['max']>0:
				count = count + 1
		elif byte>ASICC_RANGE['max']:
			count = byte / ASICC_RANGE['max']
			if byte % ASICC_RANGE['max']>0:
				count = count + 1
		#print('[*] count = %d'%count)
		maxcount = maxcount if maxcount>=count else count
	#print('[*] maxcount = %d'%maxcount)
	return maxcount



def RandomizeValue(value,mark=0):
	#value must locate between ASICC_RANGE['min'] and ASICC_RANGE['max']
	if ASICC_RANGE['min'] > value  or value > ASICC_RANGE['max']:
		print('value scope error!')
		exit(0)
	seed = min([value-ASICC_RANGE['min'],ASICC_RANGE['max']-value]) 
	#seed = randint(0,seed)
	seed = randint(0,seed/2)
	#print 'seed = 0x%02x'%seed
	if mark == 0:
		new_value = randint((value-seed),value)
	elif mark == 1: 
		new_value = randint(value,(value+seed))
	return new_value




def RandomAsiccBYTE(): return randint(ASICC_RANGE['min'],ASICC_RANGE['max'])

def RandomAsiccDWORD():
	ret = 0x00000000
	for i in xrange(0,4):
		ret += RandomAsiccBYTE() << i*8
	return ret

def CheckIsAsiccDWORD(val):
	for i in xrange(0,4):
		byte = (val >> i*8)&0xFF
		#print '0x%02x'%byte
		if ASICC_RANGE['min'] <= byte <= ASICC_RANGE['max']:
			pass
		else:
			return False
	return True

def CheckIsAsiccByte(byte):
	if ASICC_RANGE['min'] <= byte <= ASICC_RANGE['max']:
		return True
	else:
		return False
	



def PrintAsciiValueResult(AsiccValueList):
	
	result = ''
	sum = 0
	size = len(AsiccValueList)
	if size==0:
		print 'no values'

	for i in xrange(size):
		result += '0x%08x'%AsiccValueList[i]
		if i < size-1:
			result += ' + '
		sum = (sum+AsiccValueList[i])&0xFFFFFFFF
	result = '[*] 0x%08x = '%sum + result
	print result	


###############################################################################################

'''

def SeparateIntoTwoAsiccValue(val):
	count = 2
	value1 = 0x00000000
	value2 = 0x00000000
	borrow = 0
	for i in xrange(4):
		byte = (val>>i*8)&0xFF
		#print 'byte = 0x%04x' % byte
		if borrow == 1:
			byte = byte - 1
			borrow = 0
		#print 'byte = 0x%04x' % byte
		if byte < ASICC_RANGE['min'] * count:
			byte = byte + 0x100
			borrow = 1
		#print 'byte = 0x%04x' % byte
		byte1 = (byte / count)
		byte2 = byte - byte1
		if not CHeckIsAsiccByte(byte1):
			print ('[!] find bad byte1 value:0x%02x'%byte1)
			return []
		if not CHeckIsAsiccByte(byte2):
			print ('[!] find bad byte2 value:0x%02x'%byte2)
			return []

		value1 += byte1<<(i*8)
		value2 += byte2<<(i*8)

	print '[*] value1 = 0x%08x value2 = 0x%08x [value1 + value2 = 0x%08x]'%(value1,value2,(value1+value2)&0xFFFFFFFF)
	return [value1,value2]


def SeparateIntoThreeAsiccValue(val):
	count = 3
	value1 = 0x00000000
	value2 = 0x00000000
	value3 = 0x00000000
	borrow = 0
	for i in xrange(4):
		byte = (val>>i*8)&0xFF
		#print 'byte = 0x%04x' % byte
		if borrow == 1:
			byte = byte - 1
			borrow = 0
		#print 'byte = 0x%04x' % byte
		if byte < ASICC_RANGE['min'] * count:
			byte = byte + 0x100
			borrow = 1
		#print 'byte = 0x%04x' % byte
		byte1 = (byte / count)
		byte2 = (byte / count)
		byte3 = byte - byte1 - byte2
		if not CHeckIsAsiccByte(byte1):
			print ('[!] find bad byte1 value:0x%02x'%byte1)
			return []
		if not CHeckIsAsiccByte(byte2):
			print ('[!] find bad byte2 value:0x%02x'%byte2)
			return []
		if not CHeckIsAsiccByte(byte3):
			print ('[!] find bad byte3 value:0x%02x'%byte3)
			return []

		value1 += byte1<<(i*8)
		value2 += byte2<<(i*8)
		value3 += byte3<<(i*8)

	print '[*] value1 = 0x%08x value2 = 0x%08x value3 = 0x%08x [value1 + value2 + value3 = 0x%08x]'%(value1,value2,value3,(value1+value2+value3)&0xFFFFFFFF)
	return [value1,value2,value3]


def _GetAsiccValues(val):

	AsiccValueList = []
	print '[*] 0x%08x' % val
	count = GetSeparateCount(val)
	if   count == 1:
		AsiccValueList = [val]
	elif count == 2:
		AsiccValueList = SeparateIntoTwoAsiccValue(val)
		if len(AsiccValueList) == 0:
			print('[!] turn to separate Tree AsiccValues!!')
			AsiccValueList = SeparateIntoThreeAsiccValue(val)
	elif count == 3:
		AsiccValueList = SeparateIntoThreeAsiccValue(val)
	else:
		print '[!] find new condition!!!!'

	if len(AsiccValueList) == 0:
		print('[!] Fail to Separate [0x%08x] into AsiccValues !'%val)
		exit(0)

	print ['0x%08x'%x for x in AsiccValueList]
	return AsiccValueList
'''
#######################################################################################################

