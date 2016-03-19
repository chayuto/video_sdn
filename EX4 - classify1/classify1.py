import dpkt
import datetime
import socket
from mHeader import mHeader

import pickle


with open('data.pickle', 'rb') as f:
	# The protocol version used is detected automatically, so we do not
	# have to specify it.
	data = pickle.load(f)
	print len(data)

	for srcKey in data:
		dstDict = data[srcKey]
		for dstKey in dstDict:
			entryList = dstDict[dstKey]

			totalByteCount = 0

			for entry in entryList:
				totalByteCount = totalByteCount + entry.length
			

			print srcKey +' -> ' +dstKey +" : "+ str(totalByteCount)
			
			'''
			portList = {}
			
			for entry in entryList:
				keyString = "%d:%d" % (entry.sport,entry.dport)
				if keyString not in portList:
					portList[keyString] = entry.length
				else:
					oldLength = portList[keyString]
					portList[keyString] = entry.length +oldLength

			for stat in portList:
				print "%s -> %d" % (stat , portList[stat])
			'''




			
