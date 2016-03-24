
# standard includes
from pox.core import core
from pox.lib.util import dpidToStr
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
import csv
import os
from datetime import datetime
from pox.lib.recoco import Timer

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import json
import threading
import atexit

# include as part of the betta branch
from pox.openflow.of_json import *

log = core.getLogger()

sessionTime = 0
time = 0
usageList = {}

#Create custom HTTPRequestHandler class
class HTTPRequestHandler(BaseHTTPRequestHandler):
  
  #handle GET command
  def do_GET(self):

    try:
      self.send_response(200)
      #send header first
      self.send_header('Content-type','text-html')
      self.end_headers()


      self.wfile.write(json.dumps(usageList))
      '''
      rootdir = 'c:/xampp/htdocs/' #file location
      try:
        if self.path.endswith('.html'):
          f = open(rootdir + self.path) #open requested file
   
          #send code 200 response
          self.send_response(200)
   
          #send header first
          self.send_header('Content-type','text-html')
          self.end_headers()
   
          #send file content to client
          self.wfile.write(f.read())
        f.close()
      '''
      return
    except IOError:
      self.send_error(404, 'file not found')
  
def runServer():
  log.info('http server is starting...')
 
  #ip and port of servr
  #by default http server port is 80
  server_address = ('127.0.0.1', 80)
  httpd = HTTPServer(server_address, HTTPRequestHandler)
  log.info('http server is running...')
  t = threading.Thread(target=httpd.serve_forever)
  t.daemon = True
  t.start()
  '''
  POX Section
  '''



# handler for timer function that sends the requests to all the
# switches connected to the controller.
def _timer_func ():
  for connection in core.openflow._connections.values():
    connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
    connection.send(of.ofp_stats_request(body=of.ofp_port_stats_request()))
  log.debug("Sent %i flow/port stats request(s)", len(core.openflow._connections))


def _handle_FlowRemoved (event):
    log.debug("_handle_FlowRemoved")
    if event.timeout:
        return

# handler to display flow statistics received in JSON format
# structure of event.stats is defined by ofp_flow_stats()
def _handle_flowstats_received (event):
    
    global time
    time = time +1
    #stats = flow_stats_to_list(event.stats)
    #log.debug("FlowStatsReceived from %s: %s", dpidToStr(event.connection.dpid), stats)
    
    #filter only connection from a monitoring node. use con.dpid
    if dpidToStr(event.connection.dpid) != 'a0-36-9f-1e-0c-cf': #if not switch s1
        log.debug("Unrecongnised Switch (%s)",dpidToStr(event.connection.dpid))
        return #do nothing, 

    '''
    fileName = './pox/misc/' +sessionTime +'-flowStat.csv'
    with open(fileName, 'a') as csvfile:
      fieldnames = ['time','cookie','nw_src','nw_dst','packet_count','byte_count']
      writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
      '''
    #NOTE:cookie differentiate if the flow is the same entry (cookie is unique for each flow)
    for f in event.stats:
      #timeStamp[f.cookie] = datetime.now().strftime('%Y%m%d%H%M%S');
      #TEST:isolate and match ip 


      if f.byte_count != 0 and f.priority == 6000: #signature
        ip_src = str(f.match.nw_src)
        ip_dst = str(f.match.nw_dst)
        log.debug("cookie:%s Traffic: %s -> %s (%s bytes)",f.cookie,ip_src,ip_dst,f.byte_count)
        
        enteryDict = {}
        enteryDict["cookie"] = f.cookie
        enteryDict["SourceIP"] = ip_src
        enteryDict["Bytes"] = f.byte_count

        if ip_dst not in usageList:
          flowDict = {}
          flowDict[f.cookie] = enteryDict
          usageList[ip_dst] = flowDict
        else:
          flowDict = usageList[ip_dst] 
          flowDict[f.cookie] = enteryDict


    
    
# handler to display port statistics received in JSON format
def _handle_portstats_received (event):
  stats = flow_stats_to_list(event.stats)
  #log.debug("PortStatsReceived from %s: %s", 
  #  dpidToStr(event.connection.dpid), stats)
    
# main functiont to launch the module
def launch ():
  global sessionTime
  log.info("flow_stat launched")
  sessionTime = datetime.now().strftime('%Y%m%d%H%M%S') 
  # attach handsers to listners
  core.openflow.addListenerByName("FlowRemoved",
    _handle_FlowRemoved)
  core.openflow.addListenerByName("FlowStatsReceived", 
    _handle_flowstats_received) 
  core.openflow.addListenerByName("PortStatsReceived", 
    _handle_portstats_received) 

  #run http server
  runServer()
  #atexit.register(shutdownHTTPserver)


  # timer set to execute every 1 seconds
  Timer(1, _timer_func, recurring=True)