import dpkt
import datetime
import socket

from netaddr import IPNetwork, IPAddress



import pickle

def ip_to_str(address):
	return socket.inet_ntop(socket.AF_INET, address)


serviceRate = 100.0 * 1024 * 1024;
fin  = open('NF2.pcap')
pcap = dpkt.pcap.Reader(fin)
fout = open('Out.csv', 'w')


#stat collect
pkt_counter = 0
pkt_up =0
pkt_down = 0 
pkt_down_noNF = 0
pkt_down_NF = 0 
pkt_noTCP = 0

#service time storage
endServiceTime = 0;


#load AS list
servListRAW = tuple(open('./Netflix_AS2906.txt', 'r'))
networkList =[]
for i in servListRAW:
	#servList.append(i.strip()) #remove \n character at the end of the line
	networkList.append(IPNetwork(i.strip()))

#define local network
localNetwork = IPNetwork("192.168.1.0/24")


#reactive flow list
reactiveFlowList = [];


for timestamp, buf in pcap:
	
	# track number of packets
	pkt_counter += 1


	# Unpack the Ethernet frame (mac src/dst, ethertype)
	eth = dpkt.ethernet.Ethernet(buf)        
	#print 'Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type

	# Make sure the Ethernet frame contains an IP packet    
	# EtherType (IP, ARP, PPPoE, IP6... see http://en.wikipedia.org/wiki/EtherType)
	if eth.type != dpkt.ethernet.ETH_TYPE_IP:
		#print 'Non IP Packet type not supported %s\n' % eth.data.__class__.__name__    	
		continue

	# Now unpack the data within the Ethernet frame (the IP packet)     
	# Pulling out src, dst, length, fragment info, TTL, and Protocol
	ip = eth.data
	
	if ip.p == 6:

		tcp    = ip.data
		tcpsrc = tcp.sport
		tcpdst = tcp.dport
		tcpwin = tcp.win
		tcpack = tcp.ack
		tcpseq = tcp.seq
		pkt_len = len(buf)

		#make it string!
		ip_src = ip_to_str(ip.src)
		ip_dst = ip_to_str(ip.dst)


		if IPAddress(ip_dst) in localNetwork:
			#downstream traffic
			pkt_down+=1
			
			matchReact = False;

			arrivalTime = timestamp;

			
			if(arrivalTime>endServiceTime):
				#if packet arrive after end of service of previous packet
				#start service immediately
				startServiceTime = arrivalTime;
			else:
				#if packet arrive before end of service of previous packet
				#packet will be serve after previous packet is finished processing
				startServiceTime = endServiceTime;

			endServiceTime = startServiceTime + pkt_len/serviceRate

			#reactvie rule table checking #priority 100
			for entry in reactiveFlowList:
				if (entry["ip_src"] == ip_src and entry["ip_dst"] == ip_dst):

					entry["byte_count"] += pkt_len
					entry["pkt_count"] += 1;

					if entry["pkt_count"] == 1:
						entry["startTime"] = startServiceTime
						entry["endTime"] = startServiceTime
					else:
						entry["endTime"] = startServiceTime

					matchReact = True;

					pkt_down_NF +=1

					print "----"
					print "packet no: %s " % pkt_counter
					print str(datetime.datetime.utcfromtimestamp(startServiceTime))
					print "match reactive flow %s:%s:%d:%d" %  (ip_src, ip_dst,entry["pkt_count"],entry["byte_count"])
					
					break;

		
			#proactvie rule table checking #priority 100
			if(not matchReact):
				for network in networkList:
					if IPAddress(ip_src) in network:

						fout.write("%.6f,%s,%s,%s,%s,%s\n" %
						(timestamp, ip_src, tcpsrc, ip_dst, tcpdst,pkt_len))
					
						pkt_down_NF +=1

						
						#match proactive flow
						print "----"
						print "packet no: %s " % pkt_counter
						print str(datetime.datetime.utcfromtimestamp(startServiceTime))
						print "netflix pkt match proactive flow: %s" % ip_src
						print "action: install reactive flow"
						#add new reactive flow
						reactFlowEntry = {}
						reactFlowEntry["ip_src"] = ip_src
						reactFlowEntry["ip_dst"] = ip_dst
						reactFlowEntry["byte_count"] = 0;
						reactFlowEntry["pkt_count"] = 0;
						reactiveFlowList.append(reactFlowEntry);

						break;
		else:
			pkt_up +=1


	else:
		pkt_noTCP +=1

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
print "pkt_down" , pkt_down
print "pkt_up" , pkt_up
print "pkt_noTCP" , pkt_noTCP
print "pkt_down_NF" , pkt_down_NF
print "pkt_down_noNF" , pkt_down_noNF

print "================"
print "  "

for flow in reactiveFlowList:
	print "src_ip %s" % flow["ip_src"]
	print "hostname:"+socket.gethostbyaddr(flow["ip_src"])[0]
	print "dst_ip %s" % flow["ip_dst"]
	print "byte_count %d" % flow["byte_count"]
	print "pkt_count %d" % flow["pkt_count"]
	print "startTime %s" % str(datetime.datetime.utcfromtimestamp(flow["startTime"]))
	print "endTime %s" % str(datetime.datetime.utcfromtimestamp(flow["endTime"]))
	duration = flow["endTime"] - flow["startTime"]
	print "duration %.3f Sec"% duration
	print "----"
	pass