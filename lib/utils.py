import os
from subprocess import *


def tmpfile(tmpdir,filename,mode='w'):
	if not os.path.isdir(tmpdir): os.mkdir(tmpdir)
	filename = tmpdir + r'/' + filename
	fd = open(filename,mode)
	return fd

def execute_command(command, cmd_input=None):
	"""
	Execute external command and capture its output

	Args:
		- command (String)

	Returns:
		- output of command (String)
	"""
	result = ""
	P = Popen([command], stdout=PIPE, stdin=PIPE, shell=True)
	(result, err) = P.communicate(cmd_input)
	if err:
		print(err)
	return result


def check_file_exist(filepath):
	if not os.path.exists(filepath):
		print "error: file not found [%s]\n" % filepath
		return False
	return True
