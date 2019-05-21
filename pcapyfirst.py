# Code a packet sniffer - https://www.binarytides.com/code-a-packet-sniffer-in-python-with-pcapy-extension/
# Pcapy Reference - https://rawgit.com/CoreSecurity/pcapy/master/pcapy.html
# tor guard list - https://www.dan.me.uk/torlist/ https://metrics.torproject.org/rs.html
import pcapy
import socket
import struct
import datetime, time
import sys
from netutils import *

f=open(sys.path[0]+'/pcapytorguards.txt','r')
torguards=f.read().split('\n')
f.close()

import logging
#logging.basicConfig(level=logging.DEBUG, format='%(levelname)s - %(message)s')
logging.basicConfig(level=logging.DEBUG, format='%(message)s')
def print(*args): logging.debug(' '.join([str(arg) for arg in args]))
def printerr(err): print(bcolors.FAIL+str(err)+bcolors.ENDC)

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    YELLW = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
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

class _debug:
	#ether=True
	ip=False
	ipopts=False
	tcp=True
	tcpopts=True
	udp=False	
	torskip=True
	torshowskip=False

#pcapy.findalldevs()
#c = pcapy.open_live('lo' , 65536 , 1 , 0)
try: c = pcapy.open_live('wlp3s0' , 65536 , 1 , 0)
except pcapy.PcapError as e:
	if "don't have permission" in str(e): printerr('Requiere sudo')
	else: throw(e)
	sys.exit(1)


_locaddrs = ['127.0.0.1', '192.168.0.92', 'e8:de:27:39:ce:a6']
PROTS={6:'TCP',17:'UDP',1:'ICMP'}
#(intX=Xbytes)bB=int1, hH=int2, lLiI=int4, qQ=int8, sp=string, !=netorder(big-end)
upackbytes = {1:'B',2:'H',4:'L'}

_tcpconerasesecs = 5
class Tcpcon:
	def __init__(self,addr):
		self.lastt=datetime.datetime.now()
		self.addr=addr
		self.msgsin=0
		self.msgsout=0
class TcpconMgr:
	def __init__(self):
		self.conns={}
	def add(self,addr):
		self.conns[addr]=Tcpcon(addr)
		return self.conns[addr]
	def get(self,addr):
		return self.conns.get(addr)
	def update(self,addr):
		if addr in self.conns:
			self.conns[addr].lastt=datetime.datetime.now()
		else:
			self.add(addr)
		return self.conns[addr]
	def clean(self):
		dtnow=datetime.datetime.now()
		delconns=[]
		for addr,conn in self.conns.items():
			if (conn.lastt-dtnow).total_seconds() > _tcpconerasesecs:
				delconns.append(addr)
		for addr in delconns:
			del self.conns[addr]
		return len(delconns)

tcpconmgr=TcpconMgr()

def handle_packet(pkh, data):
	#getts getcaplen getlen
	ptimes=pkh.getts()
	pdate=time.localtime(ptimes[0])
	plen=pkh.getlen()
	datai=0
	print(time.strftime('%H:%M:%S', pdate)+'.'+str(ptimes[1])[:3], str(plen)+'B')

	eth_length = 14
	eth_header = data[:eth_length]
	datai += eth_length

	#(intX=Xbytes)bB=int1, hH=int2, lLiI=int4, qQ=int8, sp=string, !=netorder(big-end)
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
		''' IPv4
		 |0001020304050607|0809101112131415|1617181920212223|2425262728293031|
		1|Version | IHL   | DiffServ   |ECN|     Tot len bytes (head+data)   |          
		2|              Frag ID            |Flags |   Frag Offset            |
		3|     TTL        |    Protocol    |         Header chksum           |
		4|                             Source IP                             |
		5|                             Destin IP                             |
		[|Opt type|Opt len| 	  Opt data..           ..|..    paddding     |]
		'''
		ip_minhlen = 5*4
		ip_header = data[datai:datai+ip_minhlen]
		datai += ip_minhlen
		
		#0=V+IHL,1=DSCP+ECN,2=len,3=ID,4=Flags+FragOff,5=TTL,6=Prot,7=HeadCheck
		iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)

		version_hl = iph[0]
		version = version_hl >> 4
		iphlen = version_hl & 0xF
		#1 iphlen = 32 bit word = 4 bytes
		ttl = iph[5]
		protocol = iph[6]
		s_addr = socket.inet_ntoa(iph[8]);
		d_addr = socket.inet_ntoa(iph[9]);
		if str(s_addr) in _locaddrs:
			loc_addr = s_addr
			rem_addr = d_addr
		elif str(d_addr) in _locaddrs:
			loc_addr = d_addr
			rem_addr = s_addr
		else:
			loc_addr = rem_addr = None
		
		if _debug.torskip and str(s_addr) in torguards or str(d_addr) in torguards:
			if _debug.torshowskip: print('TorGuard', str(s_addr), '->', str(d_addr), str(plen)+'bytes')
			return

		if _debug.ip:
			print(
				'IP V:' + str(version),
				'HLen:' + str(iphlen),
				'TTL:' + str(ttl),
				'Prot:' + str(protocol) + ' ' + PROTS.get(protocol,'-'),
				'SrcIP: ' + str(s_addr),
				'DstIP: ' + str(d_addr))
			#print(str(s_addr), '>', str(d_addr), PROTS.get(protocol, str(protocol)), str(iph_length))
		
		#IP OPTS
		if iphlen>5:
			#ip Option Format - http://www.tcpipguide.com/free/t_IPDatagramOptionsandOptionFormat.htm
			#IP Option Numbers - https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
			ipopthlen=2#bytes
			firstopth = data[datai:datai+ipopthlen]
			datai+=datai+ipopthlen		
				
			firstopt = struct.unpack('!BB' , firstopth)
						
			foptcop=firstopt[0]>>8-1
			foptcla=(firstopt[0]>>8-1-2)&2**2-1
			foptnum=firstopt[0]&2**5-1
			ipoptclas = {0:'CTRL',2:'DB&M'}
			#IP Router Alert Option - https://tools.ietf.org/html/rfc2113
			ipoptnums = {20:'RTRALT'}
			foplen=firstopt[1]
			fopdata=data[datai:datai+(foplen-2)]
			
			#ip_optslen=(iphlen-5)*4
			#print('ip_opts',(iphlen-5),data[datai:datai+ip_optslen])
			
			if _debug.ipopts:
				print(
					'IPOPT fcopy={}'.format(foptcop),
					'clas={}({})'.format(ipoptclas.get(foptcla), foptcla),
					'opn={}({})'.format(ipoptnums.get(foptnum), foptnum),
					'oplen={}'.format(foplen),
					'opdata={}'.format(bytes_bin_repr(fopdata)))
		#end ip opts		

		#protocol num - https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
		#TCP
		if protocol == 6:
			tcp_minhlen = 5*4 #5 32bit words = 5*4bytes
			tcp_header = data[datai:datai+tcp_minhlen]
			datai += tcp_minhlen

			#now unpack them :)
			#TCP Header Fields - http://www.omnisecu.com/tcpip/tcp-header.php
			''' TCP
			 |0001020304050607|0809101112131415|1617181920212223|2425262728293031|
			1|            Source Port          |           Dest Port             |          
			2|                            Sequen Number                          |
			3|                             Acknow Num                            |
			4|Head Len |     Reserv     |UAPRSF|       Windw Size bytes          |
			5|             Checksum            |         Urg Pointer             |
			[|Opt type|Opt len| 	  Opt data..           ..|..    paddding     |]
			'''
			#(intX=Bytes)bB=int1, hH=int2, lLiI=int4, qQ=int8, sp=string, !=netorder(big-end)
			tcpstruct = {'srcport':2, 'dstport':2, 'seqn':4, 'ackn':4,
			'hl_res_flg':2, 'rcvwin':2, 'chck':2, 'urgp':2}
			tcpflag=['fin','syn','rst','psh','ack','urg']
			tcpfmt = '!'+''.join([upackbytes[b] for k,b in tcpstruct.items()])
			#'!HHLLBBHHH'
			tcph = struct.unpack(tcpfmt, tcp_header)
			source_port = tcph[0]
			dest_port = tcph[1]
			sequence = tcph[2]
			acknowledgement = tcph[3]
			hl_res_flg = tcph[4]
			
			tcph_length = hl_res_flg >> 4+8
			res = (hl_res_flg >> 6) & 2**6-1
			flags = hl_res_flg & 2**6-1
			print(int_bin_repr(tcph_length), tcph_length, int_bin_repr(hl_res_flg,16))
			if _debug.tcp:
				print(
					'TCP',
					*[k+'='+str(tcph[i]) for i,k in enumerate(tcpstruct) if k not in ['hl_res_flg']],
					'hlen=' + str(tcph_length),
					'res='+int_bin_repr(res, 6))					
				print('TPCFGS', *[f+'='+('0' if flags&2**i == 0 else '1' ) for i,f in enumerate(tcpflag)])
			#print(*[k+'='+str(tcph[i]) for i,k in enumerate(tcpstruct)], 'hlenw=' + str(tcph_length))
			#print(*[str(i)+'='+str(flags&2**i) for i in range(6)])
			fgfin=flags&2**0
			fgsyn=flags&2**1
			fgrst=flags&2**2
			fgpsh=flags&2**3
			fgack=flags&2**4
			fgurg=flags&2**5
			
			#tcp opts
			if tcph_length>5:
				#TCP Options - https://www.freesoft.org/CIE/Course/Section4/8.htm				
				#TCP Option Kind Numbers - https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
				tcpoptstotlen=tcph_length*4-tcp_minhlen
				tcpopthlen=1#bytes
				tcpoptkinds={0:'EOL',1:'NOOP',2:'MAXSS',8:'TIMESTP'}
				
				tcpoptsdata = data[datai:datai+tcpoptstotlen]
				datai+=tcpoptstotlen		
				#print(tcpoptsdata[0],tcpoptsdata[1],tcpoptsdata[2],bytes_bin_repr(tcpoptsdata, tcpoptstotlen))		
				
				tcpopti=0
				while tcpopti < tcpoptstotlen:
					tcpoptkind = tcpoptsdata[tcpopti]
					tcpopti+=1
												
					if tcpoptkind==0:
						if _debug.tcpopts:
							print('TCPOPT', tcpoptkinds.get(tcpoptkind,''))
						break
					elif tcpoptkind==1:
						if _debug.tcpopts:
							print('TCPOPT', tcpoptkinds.get(tcpoptkind,''))
						continue
					elif tcpoptkind==2:
						tcpoptklen = tcpoptsdata[tcpopti]
						tcpopti+=1
						if tcpoptklen!=4:
							printerr('tcp opt mss len != 4, es =' + str(tcpoptklen))
							break
						tcpmss=struct.unpack('!H' , tcpoptsdata[tcpopti:tcpopti+2])[0]
						tcpopti+=2
						if _debug.tcpopts:
							print('TCPOPT', tcpoptkinds.get(tcpoptkind,''), 'mss=', tcpmss)
					elif tcpoptkind==4:
						#https://tools.ietf.org/html/rfc2018
						printerr('TCPOPT must implement SACK Permitted')
						break
					elif tcpoptkind==8:
						#http://www.networksorcery.com/enp/protocol/tcp/option008.htm
						#https://cloudshark.io/articles/tcp-timestamp-option/
						tcpoptklen = tcpoptsdata[tcpopti]
						tcpopti+=1
						if tcpoptklen!=10:
							printerr('tcp opt timestp len != 10, es =' + str(tcpoptklen))
							break
						tcptstp=struct.unpack('!LL' , tcpoptsdata[tcpopti:tcpopti+4*2])
						tcpopti+=4*2
						if _debug.tcpopts:
							print(
								'TCPOPT', tcpoptkinds.get(tcpoptkind,''), 
								'tsval=' + str(tcptstp[0]), 
								'tsecr=' + str(tcptstp[1]))
					else:
						printerr('tcp opt desconocida ' + str(tcpoptkind))
						break
			#end tcp opts
			
			#tcp data
			if datai < plen:
				#http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session/
				sslrectyps = {20:'CHCIPHR', 21:'ALERT', 22:'HNDSHK', 23:'APPDATA'}
				if data[datai] in sslrectyps and data[datai+1] == 3:
					ssltyp=data[datai]
					print('ssl', sslrectyps.get(ssltyp), data[datai+1], data[datai+2])
			
			if rem_addr:
				remcon = tcpconmgr.update(rem_addr)
				if rem_addr == d_addr: remcon.msgsout+=1
				else: remcon.msgsin+=1
				print(remcon.msgsin,remcon.msgsout)
		
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
						printerr('invalid gzip')
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
				try: igmp_fields=struct.unpack('!BBH4sL4s',igmp_header)
				except struct.error as e:
					printerr(e)
					return
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
	tcpconmgr.clean()
	#print(r)
