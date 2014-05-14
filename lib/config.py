
#tmp dir
TMP_DIR = r'tmp'
#tools dir
TOOLS   = r'../tools/' 

# external binaries
NASM                    = r'/usr/bin/nasm'
NDISASM                 = r'/usr/bin/ndisasm'


#external binaries commands
NASM_COMMAND_FORMAT     = r'%s -f bin -o %s %s '
NDISASM_COMMAND_FORMAT  = r'%s -b %d - '


# NEDT global options
OPTIONS = {
"debug"             :   (True,"debug info"),
"system"            :   ("win32", "system version: linux / win32"),
"mode"              :   (32, "mode: 16/32/64 bits assembly"),
"search_bytes"  	:	(16, "rop gadgets search depth, 16 bytes at most"),
"pagesize"		    :	(20, "number of lines to display per page, 0 = disable paging"),
"style"             :	("intel", "assemble style for objdump \"-M\" option, intel or att "),
"title"             :	("%s  > ", "command dash info"),
"debug"             :   (False, "debug mode"),
"show_virtual"      :   (False, "display virtual address")
}


class Option(object):
    """
	bla bla bla .... >>!
    """
    options = OPTIONS.copy()

    def __init__(self):
        pass

    @staticmethod
    def reset():
        Option.options = OPTIONS.copy()
        return True

    @staticmethod
    def show(name=""):
        result = {}
        for opt in Option.options:
            if name in opt and not opt.startswith("_"):
                result[opt] = Option.options[opt][0]
        return result

    @staticmethod
    def get(name):
        if name in Option.options:
            return Option.options[name][0]
        else:
            return None

    @staticmethod
    def set(name, value):
        if name in Option.options:
            Option.options[name] = (value, Option.options[name][1])
            return True
        else:
            return False

    @staticmethod
    def help(name=""):
        result = {}
        for opt in Option.options:
            if name in opt and not opt.startswith("_"):
                result[opt] = Option.options[opt][1]
        return result
