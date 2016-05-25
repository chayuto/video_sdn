import urllib2
import os

while True:
	try:

		urlfile = urllib2.urlopen("http://ftp.acc.umu.se/mirror/cdimage.ubuntu.com/releases/14.04/release/ubuntu-14.04.3-desktop-amd64+mac.iso")

		dataLen = 0;
		data_list = []
		chunk = 40960
		while 1:
		    data = urlfile.read(chunk)
		    if not data:
		        print "done."
		        break
		        dataLen += len(data)

	except :
		print("Error")
		pass

