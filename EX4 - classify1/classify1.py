import dpkt
import datetime
import socket

import pickle

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


with open('data.pickle', 'rb') as f:
	# The protocol version used is detected automatically, so we do not
	# have to specify it.
	data = pickle.load(f)
	print len(data)

	for srcIP in data:
		dstDict = data[srcIP]
		for dstIP in dstDict:
			entryList = dstDict[dstIP]
			print srcIP +':' +dstIP +":"+ str(len(entryList))
			
