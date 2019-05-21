import sys

def eth_addr(a):
	return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a[0] , a[1] , a[2], a[3], a[4] , a[5])
		
		
def dump_decodes(barr):
	return 'hex={} || utf8={} || ascii={}'.format(barr.hex(), barr.decode('utf8','ignore'), barr.decode('ascii','ignore'))
	
	
def int_bin_repr(i, zfil=8):
	return bin(i)[2:].zfill(zfil)	
def bytes_bin_repr(byts, zfil=8):
	return int_bin_repr(int.from_bytes(byts, byteorder=sys.byteorder), zfil)
