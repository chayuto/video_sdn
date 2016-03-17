
# standard includes
from pox.core import core
from pox.lib.util import dpidToStr
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
import csv
import os
from datetime import datetime
from pox.lib.recoco import Timer

# include as part of the betta branch
from pox.openflow.of_json import *

log = core.getLogger()

sessionTime = 0
time = 0
flowList = {}

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


    fileName = './pox/misc/' +sessionTime +'-flowStat.csv'
    with open(fileName, 'a') as csvfile:
      fieldnames = ['time','cookie','nw_src','nw_dst','packet_count','byte_count']
      writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

      #NOTE:cookie differentiate if the flow is the same entry (cookie is unique for each flow)
      for f in event.stats:
        #timeStamp[f.cookie] = datetime.now().strftime('%Y%m%d%H%M%S');
        #TEST:isolate and match ip 
        if f.byte_count != 0:
          ip_src = str(f.match.nw_src)
          ip_dst = str(f.match.nw_dst)
          log.debug("cookie:%s Traffic: %s -> %s (%s bytes)",f.cookie,ip_src,ip_dst,f.byte_count)
        
          if f.cookie not in flowList:
            flowList[f.cookie] = f;
            writer.writerow({'time':time,'cookie':f.cookie,'nw_src':ip_src,'nw_dst':ip_dst,'packet_count':f.packet_count,'byte_count':f.byte_count})
          else:
            oldFlow = flowList[f.cookie];
            diffByte =  f.byte_count -oldFlow.byte_count
            diffPacket =  f.packet_count -oldFlow.packet_count
            writer.writerow({'time':time,'cookie':f.cookie,'nw_src':ip_src,'nw_dst':ip_dst,'packet_count':diffPacket,'byte_count':diffByte})
          
            flowList[f.cookie] = f; #update the static flow
    
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



  # timer set to execute every 1 seconds
  Timer(1, _timer_func, recurring=True)