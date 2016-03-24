import dpkt
import datetime
import socket

from netaddr import IPNetwork, IPAddress



import pickle


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


fin  = open('low.pcap')
pcap = dpkt.pcap.Reader(fin)
fout = open('lowOut.csv', 'a')

pkt_counter = 0


#load AS list
servListRAW = tuple(open('./Netflix_AS2906', 'r'))
networkList =[]
for i in servListRAW:
	#servList.append(i.strip()) #remove \n character at the end of the line
	networkList.append(IPNetwork(i.strip()))

firstTimestamp = pcap[0].timestamp

for timestamp, buf in pcap:
	# track number of packets
	pkt_counter += 1
	

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
	#(ip_to_str(ip.src), ip_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset)

	# Now unpack the data within the IP packet     
	# Pulling out src and dst ports
	
	if ip.p == 6:
		
		for network in networkList:
			if IPAddress(ip_to_str(ip.src)) in network:
				tcp    = ip.data
				tcpsrc = tcp.sport
				tcpdst = tcp.dport
				tcpwin = tcp.win
				tcpack = tcp.ack
				tcpseq = tcp.seq
				#print("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s" %
				#	(timestamp, ip_to_str(ip.src), tcpsrc, ip_to_str(ip.dst), tcpdst, ip.len,tcpwin,tcpack,tcpseq))
				
				#fout.write("%s,%s,%s,%s,%s,%s,%s,%s,%s\n" %
				#	(timestamp, ip_to_str(ip.src), tcpsrc, ip_to_str(ip.dst), tcpdst, ip.len,tcpwin,tcpack,tcpseq))
				
				fout.write("%s,%s\n" %
					(timestamp,  ip.len))
				print "packet no = %s" % pkt_counter
				print("%s" %(ip_to_str(ip.src)))
				break

		# size   = len(buf) 
		# ip     = eth.data
		# ipsrc  = socket.inet_ntop(AF_INET6, ip.src)
		# ipdst  = socket.inet_ntop(AF_INET6, ip.dst)
		
		# print "time= %s, Src = %s:%s, Dst = %s:%s, Len = %s"	% (ts, ipsrc, tcpsrc,  ipdst, tcpdst, size)

'''
with open('data.pickle', 'wb') as f:
	# Pickle the 'data' dictionary using the highest protocol available.
	pickle.dump(mPocket, f, pickle.HIGHEST_PROTOCOL)
'''
fout.close()
print pkt_counter