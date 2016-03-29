

"""
NX-8 Netflix capture 
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.addresses import IPAddr
import pox.lib.packet as pkt
import os
from random import randint

log = core.getLogger()
cookieCounter = 0;

def _handle_ConnectionUp (event):
  log.info("Configuring uniwideSDN: %s", dpidToStr(event.dpid))
  msg1 = of.ofp_flow_mod()
  msg1.match.in_port = 3
  msg1.priority =  10
  msg1.cookie = 11
  msg1.actions.append(of.ofp_action_output(port = 1))
  event.connection.send(msg1)
  msg2 = of.ofp_flow_mod()
  msg2.match.in_port = 1
  msg2.priority =  10
  msg2.cookie = 12
  msg2.actions.append(of.ofp_action_output(port = 3))
  event.connection.send(msg2)
  
  log.info("Current Folder" + os.getcwd())
  servListRAW = tuple(open('./pox/forwarding/Netflix_AS2906', 'r'))
  servList = []
  counter = 1000
  for i in servListRAW:
    strIn = i.strip()


    '''
    parts = strIn.split("/")
    ip = IPAddr(parts[0])
    mask = int(parts[1])
    '''

    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match()
    msg.match.in_port = 1
    msg.match.dl_type = pkt.ethernet.IP_TYPE
    msg.match.nw_proto = pkt.ipv4.TCP_PROTOCOL
    msg.match.nw_src = strIn
    #msg.match.tp_src = packet.find("udp").srcport
    #msg.match.tp_dst = packet.find("udp").dstport
    #msg.idle_timeout = 3600
    #msg.hard_timeout = 3600
    msg.cookie = counter #randint(1,999999) #set flow ID
    msg.priority =  2000
    msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
    msg
    event.connection.send(msg)
    counter = counter +1 

  log.info("Done configuring")


def _handle_PacketIn (event):

  global cookieCounter 

  packet = event.parsed
  #log.debug("Packet In")

  if event.port > of.OFPP_MAX:
    log.debug("Ignoring special port %s", event.port)
    return

  ip = packet.find('ipv4')

  if ip is None:
    log.debug("not IP packet in")

  elif event.port != 1:
    log.debug("Not downstream traffic")
  else:
    log.debug("install individual NF flow")
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match()
    msg.match.in_port = 1
    msg.match.dl_type = pkt.ethernet.IP_TYPE
    msg.match.nw_proto = pkt.ipv4.TCP_PROTOCOL
    #set new matching rule
    msg.match.nw_src = ip.srcip
    msg.match.nw_dst = ip.dstip
    #msg.match.tp_src = packet.find("udp").srcport
    #msg.match.tp_dst = packet.find("udp").dstport
    msg.idle_timeout = 60 #self remove after 1 minute
    #msg.hard_timeout = 3600
    msg.cookie = 3000 + cookieCounter #set flow ID
    cookieCounter = cookieCounter +1
    msg.priority =  6000
    msg.actions.append(of.ofp_action_output(port = 3))

    msg.data = event.ofp
    event.connection.send(msg)

    log.debug(str(ip.srcip) + " -> " + str(ip.dstip)) 


  

def launch ():
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  core.openflow.addListenerByName("PacketIn",_handle_PacketIn)
  log.info("NF_probe running.")

