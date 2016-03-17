class mHeader:
	def __init__(self,timestamp,sport,dport,length,win,ack,seq):
		self.timestamp = timestamp
		self.sport = sport
		self.dport = dport
		self.length = length
		self.win = win
		self.ack = ack
		self.seq = seq
	def getutcTimeStamp():
		return str(datetime.datetime.utcfromtimestamp(self.timestamp))