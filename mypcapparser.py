import dpkt
import datetime
import socket

import pickle


mPocket = {}


class mHeader:
	def __init__(self,timestamp,sport,dport,length,win,ack,seq):
		self.timestamp = timestamp
		self.sport = sport
		self.dport = dport
		self.len = length
		self.win = win
		self.ack = ack
		self.seq = seq

	def getutcTimeStamp():
		return str(datetime.datetime.utcfromtimestamp(self.timestamp))

def mac_addr(mac_string):
	"""Print out MAC address given a string

	Args:
	mac_string: the string representation of a MAC address
	Returns:
	printable MAC address
	"""
	return ':'.join('%02x' % ord(b) for b in mac_string)


def ip_to_str(address):
	"""Print out an IP address given a string

	Args:
	address: the string representation of a MAC address
	Returns:
	printable IP address
	"""
	return socket.inet_ntop(socket.AF_INET, address)


fin  = open('mypcap.pcap')
pcap = dpkt.pcap.Reader(fin)

pkt_counter = 0

for timestamp, buf in pcap:
	# track number of packets
	pkt_counter += 1
	print "\npacket no = %s" % pkt_counter

	# Print out the timestamp in UTC
	#print timestamp
	#print ""
	utcTimeStamp = str(datetime.datetime.utcfromtimestamp(timestamp))
	#print 'Timestamp: ', utcTimeStamp


	# Unpack the Ethernet frame (mac src/dst, ethertype)
	eth = dpkt.ethernet.Ethernet(buf)        
	#print 'Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type

	# Make sure the Ethernet frame contains an IP packet    
	# EtherType (IP, ARP, PPPoE, IP6... see http://en.wikipedia.org/wiki/EtherType)
	if eth.type != dpkt.ethernet.ETH_TYPE_IP:
		print 'Non IP Packet type not supported %s\n' % eth.data.__class__.__name__    	
		continue

	# Now unpack the data within the Ethernet frame (the IP packet)     
	# Pulling out src, dst, length, fragment info, TTL, and Protocol
	ip = eth.data

	# Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
	do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
	more_fragments = bool(ip.off & dpkt.ip.IP_MF)
	fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

	# Print out the info
	#print 'IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
	(ip_to_str(ip.src), ip_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset)

	# Now unpack the data within the IP packet     
	# Pulling out src and dst ports
	
	if ip.p == 17:
		print 'UDP packet'

	else:
		tcp    = ip.data
		tcpsrc = tcp.sport
		tcpdst = tcp.dport
		tcpwin = tcp.win
		tcpack = tcp.ack
		tcpseq = tcp.seq

		print("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s" %
			(utcTimeStamp, ip_to_str(ip.src), tcpsrc, ip_to_str(ip.dst), tcpdst, ip.len,tcpwin,tcpack,tcpseq))

		test1 = mHeader(timestamp,tcpsrc,tcpdst,ip.len,tcpwin,tcpack,tcpseq)

		ipsrc = ip_to_str(ip.src)
		ipdst = ip_to_str(ip.dst)

		if ipsrc not in mPocket:
			print 'srcIP not match'
			entryList = []
			entryList.append(test1)
			dstDict = {}#create new dstDict and store new header in a new list
			dstDict[ipdst] = entryList
			mPocket[ipsrc] = dstDict
			pass
		else:
			dstDict = mPocket[ipsrc]
			if ipdst in dstDict:
				print 'srcIP match, dstIP match'
				#update entry list
				entryList = dstDict[ipdst] 
				entryList.append(test1)
				dstDict[ipdst] = entryList

			else:
				print 'srcIP match, no dstIP'
				#create new entrylist
				entryList = []
				entryList.append(test1)
				dstDict[ipdst] = entryList

		# size   = len(buf) 
		# ip     = eth.data
		# ipsrc  = socket.inet_ntop(AF_INET6, ip.src)
		# ipdst  = socket.inet_ntop(AF_INET6, ip.dst)
		
		# print "time= %s, Src = %s:%s, Dst = %s:%s, Len = %s"	% (ts, ipsrc, tcpsrc,  ipdst, tcpdst, size)

with open('data.pickle', 'wb') as f:
	# Pickle the 'data' dictionary using the highest protocol available.
	pickle.dump(mPocket, f, pickle.HIGHEST_PROTOCOL)

print pkt_counter