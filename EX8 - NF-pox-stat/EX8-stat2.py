
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

      '''
      for ip_dst in usageList:
        flowDict = usageList[ip_dst]
        for cookie in flowDict:
          enteryDict = flowDict[cookie]

          outDict = {}
        pass
      '''


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

    #stats = flow_stats_to_list(event.stats)
    #log.debug("FlowStatsReceived from %s: %s", dpidToStr(event.connection.dpid), stats)
    
    #filter only connection from a monitoring node. use con.dpid
    if dpidToStr(event.connection.dpid) != 'a0-36-9f-1e-0c-cf': #if not switch s1
        log.debug("Unrecongnised Switch (%s)",dpidToStr(event.connection.dpid))
        return #do nothing, 

    #NOTE:cookie differentiate if the flow is the same entry (cookie is unique for each flow)
    for f in event.stats:
      #timeStamp[f.cookie] = datetime.now().strftime('%Y%m%d%H%M%S');
      #TEST:isolate and match ip 

      if f.byte_count != 0 and f.priority == 6000: #signature
        ip_src = str(f.match.nw_src)
        ip_dst = str(f.match.nw_dst)
        log.debug("cookie:%s Traffic: %s -> %s (%s bytes)",f.cookie,ip_src,ip_dst,f.byte_count)
        


        if ip_dst not in usageList:
          flowDict = {}
          #create new
          enteryDict = {}
          enteryDict["Time"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
          enteryDict["cookie"] = f.cookie
          enteryDict["SourceIP"] = ip_src
          enteryDict["Bytes"] = f.byte_count
          enteryDict["Duration"] = f.duration_sec
          enteryDict["RTime"] = 0
          enteryDict["RBytes"] = 0
          flowDict[f.cookie] = enteryDict
          enteryDict = {}
          usageList[ip_dst] = flowDict
        else:

          flowDict = usageList[ip_dst] 
          if f.cookie  not in flowDict:
            #create new
            enteryDict = {}
            enteryDict["Time"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S') 
            enteryDict["cookie"] = f.cookie
            enteryDict["SourceIP"] = ip_src
            enteryDict["Bytes"] = f.byte_count
            enteryDict["Duration"] = f.duration_sec
            enteryDict["RTime"] = 0
            enteryDict["RBytes"] = 0
            flowDict[f.cookie] = enteryDict
          else:    
            enteryDict = flowDict[f.cookie];

            #if there is change in byte count
            if enteryDict["Bytes"] != f.byte_count:
              enteryDict["Bytes"] = f.byte_count
              enteryDict["Duration"] = f.duration_sec

              if enteryDict["RTime"]  == 0 and f.duration_sec >60:
                enteryDict["RTime"] = f.duration_sec
                enteryDict["RBytes"] = f.byte_count
              elif enteryDict["RTime"]  != 0 and f.duration_sec > 90:
                timeSpan = float(f.duration_sec - enteryDict["RTime"])
                byteCount = float(f.byte_count -enteryDict["RBytes"])
                Mbps = byteCount * 8 / (timeSpan * 1024000)
                enteryDict["Mbps"] = Mbps

                if Mbps > 15:
                  enteryDict["Quality"] = "???"
                elif Mbps > 10:
                    enteryDict["Quality"] = "UHD"
                elif Mbps > 8:
                    enteryDict["Quality"] = "UHD/HD"
                elif Mbps > 5:
                    enteryDict["Quality"] = "HD"
                elif Mbps > 2:
                    enteryDict["Quality"] = "HD/SD"
                elif Mbps > 0.3:
                  enteryDict["Quality"] = "SD"
                else:
                  pass



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