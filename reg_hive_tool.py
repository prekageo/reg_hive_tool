"""
A utility that has the capability to read Microsoft Windows registry hive files,
e.g. /windows/system32/config/system. Information for the hive file format was
taken from:
http://www.reactos.org/
http://www.codeproject.com/KB/recipes/RegistryDumper.aspx

Also, the utility can do slight modifications - fixes in hive files in order to
fix the common boot problem "Windows XP could not start because the following
file is missing or corrupt: \WINDOWS\SYSTEM32\CONFIG\SYSTEM".
"""

from optparse import OptionParser
import array
import datetime
import struct

class HiveIO:
    """ Serialize and deserialize structures found in the binary hive files. """

    offsets_fmt = 'l2sh'
    offsets_size = struct.calcsize(offsets_fmt)
    value_block1_fmt = 'l2shl'
    value_block1_size = struct.calcsize(value_block1_fmt)
    value_block_fmt = value_block1_fmt + 'llhh'
    value_block_size = struct.calcsize(value_block_fmt)
    base_block_fmt = '=4sllqlllllll64s396sl3576sll'
    hbin_header_fmt = '=4sll8sql'
    key_block_fmt = '=l2shqlliiiiiilllllllhh'
    key_block_size = struct.calcsize(key_block_fmt)

    def base_block(self, buffer, offset):
        """ Read the base block. """

        t = struct.unpack_from(HiveIO.base_block_fmt, buffer, offset)
        ret = {
            'signature':t[0],
            'sequence1':t[1],
            'sequence2':t[2],
            'timestamp':t[3],
            'major':t[4],
            'minor':t[5],
            'type':t[6],
            'format':t[7],
            'root_cell':t[8],
            'length':t[9],
            'cluster':t[10],
            'filename':t[11].decode('utf_16'),
            #'reserved1':t[12],
            'checksum':t[13],
            #'reserved2':t[14],
            'boot_type':t[15],
            'boot_recover':t[16],
        }
        ret['timestamp'] = self.convert_filetime(ret['timestamp'])
        return ret;

    def hbin_header(self, buffer, offset):
        """ Read the hbin header. """

        t = struct.unpack_from(HiveIO.hbin_header_fmt, buffer, offset)
        ret = {
            'signature':t[0],
            'offset':t[1],
            'size':t[2],
            #'reserved1':t[3],
            'timestamp':t[4],
            #'spare':t[5],
        }
        ret['timestamp'] = self.convert_filetime(ret['timestamp'])
        return ret

    def convert_filetime(self, filetime):
        """ Helper method that will convert a FILETIME to python datetime. """

        if filetime != 0:
            d = 11644473600
            return datetime.datetime.fromtimestamp(filetime/10000000-d)
        return None

    def key_block(self, buffer, offset):
        """ Read a key block. """

        t = struct.unpack_from(HiveIO.key_block_fmt, buffer, offset)
        name_ofs = offset+HiveIO.key_block_size
        return {
            'offset':offset,
            'block_size':t[0],
            'block_type':t[1],
            'flags':t[2],
            'timestamp':t[3],
            'spare':t[4],
            'parent':t[5],
            'subkey_count':t[6],
            'subkey_count2':t[7],
            'subkeys':t[8],
            'subkeys2':t[9],
            'value_count':t[10],
            'offsets':t[11],
            'security':t[12],
            'class':t[13],
            'max_name_len':t[14],
            'max_class_len':t[15],
            'max_value_name_len':t[16],
            'max_value_data_len':t[17],
            'work_var':t[18],
            #'name_len':t[19],
            'class_len':t[20],
            'name':buffer[name_ofs:name_ofs+t[19]].tostring(),
        }

    def write_key_block(self, buffer, offset, key):
        """ Write a key block. """

        name_len = len(key['name'])
        data = (
            key['block_size'],
            key['block_type'],
            key['flags'],
            key['timestamp'],
            key['spare'],
            key['parent'],
            key['subkey_count'],
            key['subkey_count2'],
            key['subkeys'],
            key['subkeys2'],
            key['value_count'],
            key['offsets'],
            key['security'],
            key['class'],
            key['max_name_len'],
            key['max_class_len'],
            key['max_value_name_len'],
            key['max_value_data_len'],
            key['work_var'],
            name_len,
            key['class_len'],
        )
        struct.pack_into(HiveIO.key_block_fmt, buffer, offset, *data)
        name_ofs = offset+HiveIO.key_block_size
        buffer[name_ofs:name_ofs+name_len] = array.array('c',key['name'])

    def offsets(self, buffer, offset):
        """ Read an offsets structure. """

        t = struct.unpack_from(HiveIO.offsets_fmt, buffer, offset)
        ret = {
            'block_size':t[0],
            'block_type':t[1],
            #'count':t[2],
            'elements':[],
            #'first':t[3],
            #'hash':t[4],
        }
        offset += HiveIO.offsets_size
        element_fmt = 'l'
        for i in xrange(2*t[2]):
            t = struct.unpack_from(element_fmt, buffer, offset)
            ret['elements'].append(t[0])
            offset += struct.calcsize(element_fmt)
        return ret;

    def value_block(self, buffer, offset):
        """ Read a value block. """

        t = struct.unpack_from(HiveIO.value_block_fmt, buffer, offset)
        name_ofs = offset+HiveIO.value_block_size
        ret = {
            'block_size':t[0],
            'block_type':t[1],
            #'name_len':t[2],
            'size':t[3],
            'offset':t[4],
            'value_type':t[5],
            'flags':t[6],
            #'dummy':t[0],
            'name':buffer[name_ofs:name_ofs+t[2]].tostring(),
        }
        data_ofs = ret['offset'] + 4
        if ret['size'] & 1<<31:
            data_ofs = offset + HiveIO.value_block1_size
        size = ret['size'] & (1<<31)-1
        ret['data'] = buffer[data_ofs:data_ofs+size].tostring()
        if ret['value_type'] == 1: # REG_SZ
            ret['data'] = ret['data'].decode('utf_16')
        elif ret['value_type'] == 2: # REG_EXPAND_SZ
            ret['data'] = ret['data'].decode('utf_16')
        elif ret['value_type'] == 3: # REG_BINARY
            pass
        elif ret['value_type'] == 4: # REG_DWORD
            ret['data'] = struct.unpack('l',ret['data'])[0]
        elif ret['value_type'] == 7: # REG_MULTI_SZ
            ret['data'] = ret['data'].decode('utf_16')
        elif ret['value_type'] == 8: # REG_RESOURCE_LIST
            pass
        elif ret['value_type'] == 10: # REG_RESOURCE_REQUIREMENTS_LIST
            pass
        else:
            assert False, ret
        return ret

    def long(self, buffer, offset):
        """ Read a long - dword. """

        t = struct.unpack_from('l', buffer, offset)
        return t[0]

    def write_long(self, buffer, offset, long):
        """ Write a long - dword. """

        struct.pack_into('l', buffer, offset, long)

class MSWindowsRegistryHive:
    """ Dump and fix Microsoft Windows registry hive files. """

    def __init__(self, data):
        """
        Initialize the class by storing into appropriate fields the binary data
        of the hive file.
        """

        self.base_block = data[:0x1000]
        self.data = data[0x1000:]
        self.io = HiveIO()

    def get_data(self):
        """ Return the binary data of the hive file. """

        return (self.base_block + self.data).tostring()

    def get_base_block(self):
        """ Decode and return the base block. """

        return self.io.base_block(self.base_block, 0)

    def get_hbin_headers(self):
        """ Decode and return all the hbin headers. """

        offset = 0
        while offset < len(self.data):
            hbin = self.io.hbin_header(self.data, offset)
            offset += hbin['size']
            yield hbin

    def walk(self, offset):
        """ Walk the keys of the hive file. """

        key = self.io.key_block(self.data, offset)
        self.curr_key.append(key['name'])
        self.on_key_begin(key)
        for i in xrange(key['value_count']):
            val_ofs = self.io.long(self.data, key['offsets']+4+4*i)
            try:
                val = self.io.value_block(self.data, val_ofs)
            except AssertionError, e:
                self.on_val_exception()
        if key['subkeys'] != -1:
            item = self.io.offsets(self.data, key['subkeys'])
            for i in xrange(len(item['elements'])/2):
                if item['block_type'][1] == 'f' or item['block_type'][1] == 'h':
                    self.walk(item['elements'][2*i])
                else:
                    subitem = self.io.offsets(self.data, item['elements'][i])
                    for j in xrange(len(subitem['elements'])/2):
                        mul = 2 if item['block_type'][1] == 'i' else 1
                        self.walk(subitem['elements'][mul*i])
        self.on_key_end(key)
        self.curr_key.pop()

    def init_walk(self):
        """
        Initialize fields before starting the BFS traversal of the hive's keys.
        """

        self.curr_key = []

    def fix(self):
        """
        Attempt to fix errors in the hive file. At the moment, two corrections
        are being applied:
        1. Discard information for the volatile registry keys.
        2. When a value block contains malformed data, log an error and ignore
        the value.
        """

        self.init_walk()
        state = {}
        def on_key_begin(key):
            key['subkeys2'] = -1;
            key['subkey_count2'] = 0;
            state['invalid_vals'] = []
        def on_key_end(key):
            if len(state['invalid_vals']) > 0:
                val_ofs = []
                for i in xrange(key['value_count']):
                    val_ofs.append(self.io.long(self.data, key['offsets']+4+4*i))
                for i in state['invalid_vals']:
                    del val_ofs[i]
                key['value_count'] -= len(state['invalid_vals'])
                for i in xrange(key['value_count']):
                    self.io.write_long(self.data, key['offsets']+4+4*i, val_ofs[i])
            self.io.write_key_block(self.data, key['offset'], key)
        def on_val_exception():
            path = '/'.join(self.curr_key)
            sys.stderr.write('Invalid value at %s\n' % (path,))
            state['invalid_vals'].append(i)
        self.on_key_begin = on_key_begin
        self.on_key_end = on_key_end
        self.on_val_exception = on_val_exception
        self.walk(0x20)
        return self.get_data()

    def dump(self, ignore_fields):
        """ Dump the key blocks contained in the hive file. """

        self.init_walk()
        def on_key_begin(key):
            timestamp = key.pop('timestamp')
            offsets = key.pop('offsets')
            print key
            key['timestamp'] = timestamp
            key['offsets'] = offsets
        def on_key_end(key):
            pass
        def on_val_exception(key):
            pass
        self.on_key_begin = on_key_begin
        self.on_key_end = on_key_end
        self.on_val_exception = on_val_exception
        self.walk(0x20)

#class UsageBitmap:
#    def __init__(self, size):
#        self.size = size
#        self.marked = set()
#
#    def mark(self, offset, size):
#        for i in xrange(size):
#            self.marked.add(offset+i)
#
#    def get_unmarked(self):
#        for i in xrange(self.size):
#            if i not in self.marked:
#                yield i

def main():
    """ Parse the command line arguments and execute the requested action. """

    parser = OptionParser()
    parser.add_option('-d', '--dump', dest='dump', metavar='FILE',
        help='Dump keys from registry hive FILE to stdout')
    parser.add_option('', '--ignore-fields', dest='ignore_fields',
        action='store_true',help='Do not dump timestamp and offsets fields')
    parser.add_option('-f', '--fix', dest='fix', metavar='FILE',
        help='Fixes registry hive FILE')
    parser.add_option('-O', '--output', dest='output', metavar='FILE',
        help='Write fixed registry hive to FILE')
    (options, args) = parser.parse_args()

    if options.dump and not options.fix:
        action = 'dump'
        input = options.dump
    elif not options.dump and options.fix:
        if not options.output:
            print 'Give the output file for the fixed registry hive.'
            return
        action = 'fix'
        input = options.fix
    else:
        print 'Ambiguous command line arguments.'
        return

    hive = MSWindowsRegistryHive(array.array('c',open(input,'rb').read()))
    if action == 'dump':
        hive.dump(options.ignore_fields)
    elif action == 'fix':
        open(options.output,'wb').write(hive.fix())

if __name__ == '__main__':
    main()
