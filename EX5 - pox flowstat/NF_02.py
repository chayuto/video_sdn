

"""
Turns your complex OpenFlow switches into stupid hubs.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.addresses import IPAddr
import pox.lib.packet as pkt
import os
from random import randint

log = core.getLogger()


def _handle_ConnectionUp (event):
  msg1 = of.ofp_flow_mod()
  msg1.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
  event.connection.send(msg1)
  log.info("Hubifying %s", dpidToStr(event.dpid))

  log.info("Current Folder" + os.getcwd())
  servListRAW = tuple(open('./pox/forwarding/Netflix_AS2906', 'r'))
  servList = []
  counter = 1000
  for i in servListRAW:
    strIn = i.strip()
    parts = strIn.split("/")
    ip = IPAddr(parts[0])
    mask = int(parts[1])

    
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match()
    msg.match.in_port = 2
    msg.match.dl_type = pkt.ethernet.IP_TYPE
    msg.match.nw_proto = pkt.ipv4.TCP_PROTOCOL
    msg.match.nw_src = strIn
    #msg.match.tp_src = packet.find("udp").srcport
    #msg.match.tp_dst = packet.find("udp").dstport
    msg.idle_timeout = 3600
    msg.hard_timeout = 3600
    msg.cookie = counter #randint(1,999999) #set flow ID
    msg.priority =  50000
    msg.actions.append(of.ofp_action_output(port = 1))
    event.connection.send(msg)
    counter = counter +1 
    

def launch ():
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)

  log.info("Hub running.")
