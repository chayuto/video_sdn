import dpkt
import datetime
import socket

from mHeader import mHeader

import pickle

def mean(data):
	"""Return the sample arithmetic mean of data."""
	n = len(data)
	if n < 1:
		raise ValueError('mean requires at least one data point')
	return sum(data)/n # in Python 2 use sum(data)/float(n)

def _ss(data):
	"""Return sum of square deviations of sequence data."""
	c = mean(data)
	ss = sum((x-c)**2 for x in data)
	return ss

def pstdev(data):
	"""Calculates the population standard deviation."""
	n = len(data)
	if n < 2:
		raise ValueError('variance requires at least two data points')
	ss = _ss(data)
	pvar = ss/n # the population variance
	return pvar**0.5


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
			packetSizeList = [];
			windowList = []


			for entry in entryList:
				totalByteCount = totalByteCount + entry.length
				packetSizeList.append(entry.length)
				windowList.append(entry.win)

			if totalByteCount > 1000000:

				print ""
				print srcKey +' -> ' +dstKey 
				TimeLength = entryList[-1].timestamp - entryList[0].timestamp
				print "TimeLength: " +str(TimeLength)
				print "Bytes: "+ str(totalByteCount)
				packetCount = len(entryList)
				print "Packet count: " + str(packetCount)
				print "Avg Packet Size: " + str(totalByteCount/packetCount)
				print "Packet Size SD: " + str(pstdev(packetSizeList))
				print "Window Size SD: " + str(pstdev(windowList))
				print "Avg Speed: " + str(totalByteCount*8/TimeLength)

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





			
