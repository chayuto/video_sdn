
# standard includes
from pox.core import core
from pox.lib.util import dpidToStr
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
import csv
import os
from datetime import datetime
from pox.lib.recoco import Timer

import json
import threading
import atexit

from flask import Flask

app = Flask(__name__)



    
# include as part of the betta branch
from pox.openflow.of_json import *

log = core.getLogger()

sessionTime = 0
time = 0
usageList = {}

@app.route('/')
def hello_world():
  outDict = {}
      
  for ip_dst in usageList:

    mList = [];
    flowDict = usageList[ip_dst]
    for cookie in flowDict:
      entryDict = flowDict[cookie]
      newDict = {}
      newDict["Time"] = entryDict["Time"];
      newDict["SourceIP"] = entryDict["SourceIP"]
      newDict["Bytes"] = entryDict["Bytes"]

      if "Mbps" in entryDict:
        newDict["Mbps"] = entryDict["Mbps"]
      if "Quality" in entryDict:
        newDict["Quality"]= entryDict["Quality"]
      mList.append(newDict)

    outDict[ip_dst] = mList;

  return json.dumps(outDict)
  
def runServer():
  log.info('http server is running...')
  t = threading.Thread(target=app.run)
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
        ip_dst = str(f.match.nw_dst) + ":" + str(f.match.tp_dst)
        log.debug("cookie:%s Traffic: %s -> %s (%s bytes)",f.cookie,ip_src,ip_dst,f.byte_count)
        
        if ip_dst not in usageList:
          flowDict = {}
          #create new
          entryDict = {}
          entryDict["Time"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
          entryDict["cookie"] = f.cookie
          entryDict["SourceIP"] = ip_src
          entryDict["Bytes"] = f.byte_count
          entryDict["Duration"] = f.duration_sec
          entryDict["RTime"] = 0
          entryDict["RBytes"] = 0
          flowDict[f.cookie] = entryDict
          entryDict = {}
          usageList[ip_dst] = flowDict
        else:

          flowDict = usageList[ip_dst] 
          if f.cookie  not in flowDict:
            #create new
            entryDict = {}
            entryDict["Time"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S') 
            entryDict["cookie"] = f.cookie
            entryDict["SourceIP"] = ip_src
            entryDict["Bytes"] = f.byte_count
            entryDict["Duration"] = f.duration_sec
            entryDict["RTime"] = 0
            entryDict["RBytes"] = 0
            flowDict[f.cookie] = entryDict
          else:    
            entryDict = flowDict[f.cookie];

            #if there is change in byte count
            if entryDict["Bytes"] != f.byte_count:
              entryDict["Bytes"] = f.byte_count
              entryDict["Duration"] = f.duration_sec

              if entryDict["RTime"]  == 0 and f.duration_sec >60:
                entryDict["RTime"] = f.duration_sec
                entryDict["RBytes"] = f.byte_count
              elif entryDict["RTime"]  != 0 and f.duration_sec > 90:
                timeSpan = float(f.duration_sec - entryDict["RTime"])
                byteCount = float(f.byte_count -entryDict["RBytes"])
                Mbps = byteCount * 8 / (timeSpan * 1024000)
                entryDict["Mbps"] = Mbps

                if Mbps > 15:
                  entryDict["Quality"] = "???"
                elif Mbps > 10:
                    entryDict["Quality"] = "UHD"
                elif Mbps > 8:
                    entryDict["Quality"] = "UHD/HD"
                elif Mbps > 5:
                    entryDict["Quality"] = "HD"
                elif Mbps > 2:
                    entryDict["Quality"] = "HD/SD"
                elif Mbps > 0.3:
                  entryDict["Quality"] = "SD"
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