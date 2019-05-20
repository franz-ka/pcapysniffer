# Code a packet sniffer - https://www.binarytides.com/code-a-packet-sniffer-in-python-with-pcapy-extension/
# Pcapy Reference - https://rawgit.com/CoreSecurity/pcapy/master/pcapy.html
# tor guard list - https://www.dan.me.uk/torlist/ https://metrics.torproject.org/rs.html
import pcapy
import socket
import struct
import datetime, time
import sys

f=open(sys.path[0]+'/pcapytorguards.txt','r')
torguards=f.read().split('\n')
f.close()

import logging
#logging.basicConfig(level=logging.DEBUG, format='%(levelname)s - %(message)s')
logging.basicConfig(level=logging.DEBUG, format='%(message)s')
logging.debug('Start of program')
def print(*args): logging.debug(' '.join([str(arg) for arg in args]))

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    YELLW = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

PROTS={6:'TCP',17:'UDP',1:'ICMP'}

#pcapy.findalldevs()
c = pcapy.open_live('wlp3s0' , 65536 , 1 , 0)
#c = pcapy.open_live('lo' , 65536 , 1 , 0)

def eth_addr(a):
	return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a[0] , a[1] , a[2], a[3], a[4] , a[5])

_locaddrs = ['127.0.0.1', '192.168.0.92', 'e8:de:27:39:ce:a6']
_loccol = bcolors.OKGREEN
_remcol = bcolors.YELLW
def print_ipaddrs(scraddr, dstaddr):	
	if str(scraddr) in _locaddrs:
		locaddr=_loccol+str(scraddr)
		condir='->'
		remaddr=_remcol+str(dstaddr)
	elif str(dstaddr) in _locaddrs:
		locaddr=_loccol+str(dstaddr)
		condir='<-'
		remaddr=_remcol+str(scraddr)
	else:
		locaddr=_remcol+str(scraddr)
		condir='->'
		remaddr=_remcol+str(dstaddr)
	return '{} {} {}'.format(locaddr+bcolors.ENDC, condir, remaddr+bcolors.ENDC)	
def print_addrs(scraddr, srcport, dstaddr, dstport):				
	if str(scraddr) in _locaddrs:
		locaddr=_loccol+str(scraddr)+':'+str(srcport)
		condir='->'
		remaddr=_remcol+str(dstaddr)+':'+str(dstport)
	elif str(dstaddr) in _locaddrs:
		locaddr=_loccol+str(dstaddr)+':'+str(dstport)
		condir='<-'
		remaddr=_remcol+str(scraddr)+':'+str(srcport)
	else:
		locaddr=_remcol+str(scraddr)+':'+str(srcport)
		condir='->'
		remaddr=_remcol+str(dstaddr)+':'+str(dstport)
	return '{} {} {}'.format(locaddr+bcolors.ENDC, condir, remaddr+bcolors.ENDC)	
def print_ethaddrs(srcaddr, dstaddr):
	return print_ipaddrs(srcaddr, dstaddr)
		
def dump_decodes(barr):
	return 'hex={} || utf8={} || ascii={}'.format(barr.hex(), barr.decode('utf8','ignore'), barr.decode('ascii','ignore'))
	
#(intX=Bytes)bB=int1, hH=int2, lLiI=int4, qQ=int8, sp=string, !=netorder(big-end)
#Hsport,Hdport,Lseqn,Lackn,BBhlen-res-flags,Hwsize,Hchck,Hurget..Lopts
upackbytes = {1:'B',2:'H',4:'L'}
		
def handle_packet(pkh, data):
	#getts getcaplen getlen
	ptimes=pkh.getts()
	pdate=time.localtime(ptimes[0])
	plen=pkh.getlen()
	datai=0
	#print(time.strftime('%H:%M:%S', pdate)+'.'+str(ptimes[1])[:3], str(plen)+'B')

	eth_length = 14
	eth_header = data[:eth_length]
	datai += eth_length

	#(intX=Bytes)bB=int1, hH=int2, lLiI=int4, qQ=int8, sp=string, !=netorder(big-end)
	eth = struct.unpack('!6s6sH' , eth_header)
	eth_type = eth[2]
	#eth_protocol = socket.ntohs(eth[2])
	#print('Destination MAC : ' + eth_addr(s[0:6]) + ' Source MAC : ' + eth_addr(s[6:12]) + ' Protocol : ' + str(eth_protocol))
	#print('DstMAC:', eth_addr(eth[0]), ' SrcMAC:', eth_addr(eth[1]))
	
	#EtherType - https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
	#IP
	#if eth_protocol == 8:
	if eth_type == 2048:
		#https://en.wikipedia.org/wiki/IPv4#Header
		ip_minhlen = 5*4
		ip_header = data[datai:datai+ip_minhlen]
		datai += ip_minhlen
		#0=V+IHL,1=DSCP+ECN,2=len,3=ID,4=Flags+FragOff,5=TTL,6=Prot,7=HeadCheck
		iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)

		version_hl = iph[0]
		version = version_hl >> 4
		iphlen = version_hl & 0xF
		#iph_length = iphlen * 4 #32 bit words=4 bytes
		#opts
		if iphlen>5:
			ip_optslen=(iphlen-5)*4
			print('ip_opts',(iphlen-5),data[datai:datai+ip_optslen])
			datai+=ip_optslen

		ttl = iph[5]
		protocol = iph[6]
		s_addr = socket.inet_ntoa(iph[8]);
		d_addr = socket.inet_ntoa(iph[9]);
		if str(s_addr) in torguards or str(d_addr) in torguards:
			#print('TorGuard')
			return

		#print('V:' + str(version), 'TTL:' + str(ttl), 'Prot:' + str(protocol), 'SrcIP: ' + str(s_addr), 'DstIP: ' + str(d_addr))
		#print(str(s_addr), '>', str(d_addr), PROTS.get(protocol, str(protocol)), str(iph_length))

		#protocol num https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
		#TCP
		if protocol == 6:
			tcp_minhlen = 5*4 #5 * 32bit words (4bytes)
			tcp_header = data[datai:datai+tcp_minhlen]
			datai += tcp_minhlen

			#now unpack them :)
			#TCP Header Fields - http://www.omnisecu.com/tcpip/tcp-header.php
			#(intX=Bytes)bB=int1, hH=int2, lLiI=int4, qQ=int8, sp=string, !=netorder(big-end)
			tcpstruct = {'srcport':2, 'dstport':2, 'seqn':4, 'ackn':4,
			'hl_res':1, 'flags':1, 'rcvwin':2, 'chck':2, 'urgp':2}
			#'!HHLLBBHHH'
			tcpfmt = '!'+''.join([upackbytes[b] for k,b in tcpstruct.items()])
			tcph = struct.unpack(tcpfmt, tcp_header)
			source_port = tcph[0]
			dest_port = tcph[1]
			sequence = tcph[2]
			acknowledgement = tcph[3]
			hl_res = tcph[4]
			tcph_length = hl_res >> 4
			res=hl_res&(2**7-1)
			flags=tcph[5]
			print(*[k+'='+str(tcph[i]) for i,k in enumerate(tcpstruct) if k not in ['srcport','dstport','hl_res','flags']], 'hlenw=' + str(tcph_length), 'res='+bin(res)[2:].zfill(6))
			#print(*[k+'='+str(tcph[i]) for i,k in enumerate(tcpstruct)], 'hlenw=' + str(tcph_length))
			#print(*[str(i)+'='+str(flags&2**i) for i in range(6)])
			tcpflag=['fin','syn','rst','psh','ack','urg']
			print(*[f+'='+('0' if flags&2**i == 0 else '1' ) for i,f in enumerate(tcpflag)])
			fgfin=flags&2**0
			fgsyn=flags&2**1
			fgrst=flags&2**2
			fgpsh=flags&2**3
			fgack=flags&2**4
			fgurg=flags&2**5
			#opts
			if tcph_length>5:
				tcp_optslen=(tcph_length-5)*4
				#print('tcp_opts',tcph_length-5,bin(int.from_bytes(data[datai:datai+tcp_optslen],byteorder='big')))
				datai+=tcp_optslen
				
			'''if str(s_addr) in ['127.0.0.1', '192.168.0.92']:
				locaddr=str(s_addr)+':'+str(source_port)
				condir='->'
				remaddr=str(d_addr)+':'+str(dest_port)
			elif str(d_addr) in ['127.0.0.1', '192.168.0.92']:
				locaddr=str(d_addr)+':'+str(dest_port)
				condir='<-'
				remaddr=bcolors.YELLW+str(s_addr)+':'+str(source_port)'''
				
			print(
				PROTS.get(protocol, str(protocol))[0], 
				print_addrs(s_addr, source_port, d_addr, dest_port), 
				str(plen-datai)+'bytes',
				'('+str(plen)+'bytes)',
				'S-'+str(sequence)[-4:],
				'A-'+str(acknowledgement)[-4:])
			if plen-datai>0:
				#ascii latin-1
				decdata=data[datai:].decode("utf8", "ignore")
				#print(decdata)
				if decdata.find('Content-Encoding: gzip')>0:
					ss='Content-Type: text/html'
					si=decdata.find(ss)
					import io, gzip
					#print('---',[c for c in decdata[si+len(ss)-1:si+len(ss)+6]])
					
					#f = gzip.open(io.BytesIO(decdata[si+len(ss)+1].encode("utf8")), 'rb')					
					try: 
						f = gzip.open(io.BytesIO(bytes(data[datai+si+len(ss)+2*2:])), 'rb')
						ungzip = f.read()
						print(ungzip)
					except: 
						print('invalid gzip')
					finally:
						f.close()
				#print(data[datai:].hex())

			#print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))

		#UDP
		elif protocol == 17:
			udp_minhlen = 2*4 #2 * 32bit words (4bytes)
			udp_header = data[datai:datai+udp_minhlen]
			datai += udp_minhlen
			
			#UDP Header Fields - http://www.omnisecu.com/tcpip/udp-user-datagram-protocol.php
			#(intX=Bytes)bB=int1, hH=int2, lLiI=int4, qQ=int8, sp=string, !=netorder(big-end)
			udpstruct = {'srcport':2, 'dstport':2, 'len':2, 'chk':2}
			udpfmt = '!'+''.join([upackbytes[b] for k,b in udpstruct.items()])
			udph = struct.unpack(udpfmt, udp_header)
			
			
			print('U', print_addrs(s_addr, udph[0], d_addr, udph[1]), '{}bytes ({}bytes)'.format(plen-datai, plen), 'chk='+str(udph[3]))
			if plen-datai>0:
				pass
				#print(dump_decodes(data[datai:datai+20]))
		#ICMP
		elif protocol == 1:
			icmp_minhlen = 1*4 #1 * 32bit words (4bytes)
			icmp_header = data[datai:datai+icmp_minhlen]
			datai += icmp_minhlen
			
			#ICMP Header Fields - http://www.networksorcery.com/enp/Protocol/icmp.htm
			#(intX=Bytes)bB=int1, hH=int2, lLiI=int4, qQ=int8, sp=string, !=netorder(big-end)
			icmpstruct = {'type':1, 'code':1, 'chk':2}
			icmpfmt = '!'+''.join([upackbytes[b] for k,b in icmpstruct.items()])
			icmph = struct.unpack(icmpfmt, icmp_header)
			icmptypes={0:'echo-reply', 3:'dest-unrch', 5:'redir', 8:'echo-req', 30:'trace'}
			#icmp sub types - https://rlworkman.net/howtos/iptables/chunkyhtml/a6339.html
			print(
				'I',
				print_ipaddrs(s_addr, d_addr),
				'{}bytes ({}bytes)'.format(plen-datai, plen),
				icmph[0],
				icmptypes.get(icmph[0]),
				icmph[1])
			if plen-datai>0:
				pass#print(dump_decodes(data[datai:datai+20]))
		#IGMP
		elif protocol == 2:
			# https://en.wikipedia.org/wiki/Internet_Group_Management_Protocol
			# https://en.wikipedia.org/wiki/224.0.0.22
			if str(d_addr) == '224.0.0.22':
				igmp_header=data[datai:datai+4*4]
				igmp_fields=struct.unpack('!BBH4sL4s',igmp_header)
				print('IGMPv3',plen, plen-datai, data[datai:datai+8], data[datai+8:datai+16])
				print(hex(igmp_fields[0]),igmp_fields[1],'chk='+str(igmp_fields[2]),socket.inet_ntoa(igmp_fields[3]),socket.inet_ntoa(igmp_fields[5]))
				#239.255.255.250 - https://en.wikipedia.org/wiki/Simple_Service_Discovery_Protocol
			else:
				print('IGMP',plen)
				print('DstMAC:', eth_addr(eth[0]), ' SrcMAC:', eth_addr(eth[1]))
				print('V:' + str(version), 'TTL:' + str(ttl), 'Prot:' + str(protocol), 'SrcIP: ' + str(s_addr), 'DstIP: ' + str(d_addr))
		else:
			print('protocol',protocol, plen)
	elif eth_type == 2054:
		arp_minhlen = 2*4 #2 * 32bit words (4bytes)
		arp_header = data[datai:datai+arp_minhlen]
		datai += arp_minhlen
			
		arpstruct = {'hwtype':2, 'prottype':2, 'hwaddl':1, 'protaddl':1, 'oppcode':2}
		arpfmt = '!'+''.join([upackbytes[b] for k,b in arpstruct.items()])
		arph = struct.unpack(arpfmt, arp_header)
		#arp codes http://www.networksorcery.com/enp/protocol/ARP.htm
		arpcodes={0:'resrv', 1:'req', 2:'rep', 3:'req-rev', 4:'rep-rev'}
		print('A', print_ethaddrs(eth_addr(eth[0]), eth_addr(eth[1])), arph[4], arpcodes.get(arph[4]), 'Len:', plen)
	else:
		#print('eth_protocol', eth_protocol)
		print('DstMAC:', eth_addr(eth[0]), ' SrcMAC:', eth_addr(eth[1]), ' EthType:', eth[2], 'Len:', plen)
	#print()




r = c.dispatch(5, handle_packet)
#print(r)
while 1:
	time.sleep(0.5)
	r = c.dispatch(10, handle_packet)
	#print(r)
