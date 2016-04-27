# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import ofctl_v1_3 as ofctl
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.ofproto import ofproto_v1_3 as ofp
from ryu.ofproto import ofproto_v1_3_parser as parser

from ryu.lib import hub
#from ryu.lib.packet import ether_types

from flask import Flask
import threading

from broccoli import *
import time, os, random, json

from influxdb import InfluxDBClient


app = Flask(__name__)


# TODO: configurable
INFLUXDB_DB = "gauge"
INFLUXDB_HOST = "faucet-2"
INFLUXDB_PORT = 8086
INFLUXDB_USER = ""
INFLUXDB_PASS = ""


def ship_points_to_influxdb(points):
    client = InfluxDBClient(
        host=INFLUXDB_HOST, port=INFLUXDB_PORT,
        username=INFLUXDB_USER, password=INFLUXDB_PASS,
        database=INFLUXDB_DB, timeout=10)
    return client.write_points(points=points, time_precision='s')


'''flasl stuff'''
@app.route('/')
def hello_world():
  

  return "hello_world"
  
def runServer():
  t = threading.Thread(target=app.run)
  t.daemon = True
  t.start()

ryuNFApp = 0;

'''RYU stuff'''

class ryu_nf1(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]


    def __init__(self, *args, **kwargs):
        super(ryu_nf1, self).__init__(*args, **kwargs)
        global ryuNFApp 
        ryuNFApp = self
        self.datapaths = {}
        self.logger.debug("Init");
        self.logger.debug("Start Serv");
        #runServer()
        self.logger.debug("Start ");
        self.bc = Connection("127.0.0.1:47758")
        self.monitor_thread = hub.spawn(self._monitor)

    def _monitor(self):

        while True:
            self.bc.processInput();
            #self.logger.debug("Monitor");
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(1)

    def _request_stats(self,datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        self.logger.info("switch_features_handler")

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        #self.add_flow(datapath, 0, match, actions)


        #default flows
        self.default_flows_initiation(datapath)

    
        #proactive rules
        netflix_src_list = tuple(open('./Netflix_AS2906', 'r'))
        
        for netflix_srcc in netflix_src_list:
            # self.logger.info("initiating and inserting netflix src flow entry: %s", netflix_srcc)
            netflix_src=netflix_srcc.strip()

            flowmods = self.netflix_flows_mod(datapath, netflix_src)
            # self.logger.info("after creating flowmods")
            datapath.send_msg(flowmods)
        


    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def default_flows_initiation(self,datapath):

        self.NFdatapath = datapath


        gatewayPort = 1
        clientPort = 2
        mirrorPort = 3 #not use here 
        priority = 100

        #server -> client
        match = parser.OFPMatch(in_port=gatewayPort)

        action1 = parser.OFPActionOutput(clientPort,0);
        actions = [action1]

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, cookie=0x44,  priority=priority, table_id = 0, 
                                match=match, command=ofp.OFPFC_ADD, instructions=inst, hard_timeout=0,
                                idle_timeout=0,
                                flags=ofp.OFPFF_SEND_FLOW_REM)
        datapath.send_msg(mod);



        #Client -> Server 
        match = parser.OFPMatch(in_port=clientPort)

        action1 = parser.OFPActionOutput(gatewayPort,0);
        actions = [action1]

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, cookie=0x45,  priority=priority, table_id = 0, 
                                match=match, command=ofp.OFPFC_ADD, instructions=inst, hard_timeout=0,
                                idle_timeout=0,
                                flags=ofp.OFPFF_SEND_FLOW_REM)
        datapath.send_msg(mod);


    def netflix_flows_mod(self,dp, netflix_src):
        datapath = dp

        gatewayPort = 1
        clientPort = 2
        mirrorPort = 3 

        parser = datapath.ofproto_parser

        src_ip = netflix_src
        part=src_ip.split("/")
        ip=part[0]
        self.logger.info(ip)
        mask="255.255.255.0"
        match = parser.OFPMatch(eth_type = 0x0800,ipv4_src=(ip,mask))
        # self.logger.info("after ofpmatch")
        priority = 10000

        # TODO change instruction 

        action1 = parser.OFPActionOutput(clientPort);
        action2 = parser.OFPActionOutput(mirrorPort);
        actionController = parser.OFPActionOutput(ofp.OFPP_CONTROLLER);
        actions = [action1,action2 ] #
        #actions = [action1 ] #
        # self.logger.info("after actions")
        # self.logger.info("dp: %s, srcIp: %s match: %s priority: %s actions: %s", datapath, src_ip, match, priority, actions)
        
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                             actions)]
        # self.logger.info("after inst")
        
        mod = parser.OFPFlowMod(datapath=datapath, cookie=0x3309,  priority=priority, table_id = 0, 
                                match=match, command=ofp.OFPFC_ADD, instructions=inst, hard_timeout=0,
                                idle_timeout=0,
                                flags=ofp.OFPFF_SEND_FLOW_REM)
        return mod


    def netfilx_reactive_flow_mod(self,srcIP,dstIP):

        gatewayPort = 1
        clientPort = 2
        mirrorPort = 3 

        match = parser.OFPMatch(ipv4_src=srcIP,ipv4_dst=dstIP,in_port=gatewayPort)
        # self.logger.info("after ofpmatch")
        priority = 20000

        # TODO change instruction 

        action1 = parser.OFPActionOutput(clientPort);
        actionController = parser.OFPActionOutput(ofp.OFPP_CONTROLLER);
        actions = [action1]
        # self.logger.info("after actions")
        # self.logger.info("dp: %s, srcIp: %s match: %s priority: %s actions: %s", datapath, src_ip, match, priority, actions)
        
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                             actions)]
        # self.logger.info("after inst")
        
        mod = parser.OFPFlowMod(datapath=self.NFdatapath, cookie=0x5500,  priority=priority, table_id = 0, 
                                match=match, command=ofp.OFPFC_ADD, instructions=inst, hard_timeout=0,
                                idle_timeout=0,
                                flags=ofp.OFPFF_SEND_FLOW_REM)



        return mod


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        self.logger.debug("packet_In");


    '''Event'''
    @event
    def new_nf_detect(a,b,c,d):
        ryuNFApp.logger.debug("New NF Detect");
        print repr(a), a
        print repr(b), b
        print repr(c), c
        print repr(d), d
        

    ''' stat event handler'''
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        rcv_time = time.time()
        msg = ev.msg
        body = msg.body


        self.logger.info("Flow Stat received");

        fTable = [flow for flow in body if (flow.table_id == 0)];

        self.logger.info("Size: " +str(len(fTable)));


        testPoints = []
        #[flow for flow in body if (flow.priority == 20000 and flow.table_id == 0)]
        for f in fTable:
            #for f in [flow for flow in body]:

                dpid  = msg.datapath.id
                cookie = f.cookie
                packet_count = f.packet_count
                byte_count = f.byte_count

                '''
                self.logger.info('%016x %8x %8d %8d',
                                msg.datapath.id,
                                f.instructions[0].actions[0].port,
                                f.packet_count, f.byte_count)
                

                logfile.write("time: {0}\nref: {1}\nmsg: {2}\n".format(
                msg.datapath.id, f.cookie, f.byte_count)) 
                '''
                
                #Test Influx DB stuff
                testTags = {         
                        "flow_id":cookie,
                        }

                testPoints.append({
                            "measurement": "test1",
                            "tags": testTags,
                            "time": int(rcv_time),
                            "fields": {"value": int(f.byte_count + random.randint(1, 1000)) } })
            

                '''checking'''  
                if byte_count == 0:
                    continue

                #if (not hasattr(f.match, 'tcp_src') or not hasattr(a, 'tcp_dst')):
                 #   logfile.write("match: {0}\n".format(str(f.match))) 
                  #  continue

                logfile.write("Found Flow of Interest") 
                
                ip_src = str(f.match['ipv4_src'])
                ip_dst = str(f.match['ipv4_dst'])

                #process raw info and push to Influx DB
                #TODO: more processing
                points = []

                #Influx DB stuff

                if(f.match['tcp_src'] == 80):
                    endPointStr = "Mobile"
                else:
                    endPointStr = "Web browser"

                tags = {
                        "dst_ip": ip_dst,
                        "src_ip": ip_src,
                        "src_port":f.match['tcp_src'],
                        "dst_port":f.match['tcp_dst'],
                        "flow_id":cookie,
                        "Endpoint":endPointStr
                        }


                if cookie not in self.usageDict:
                    flowDict = {}
                    
                    flowDict["Time"] = int(rcv_time)
                    flowDict["cookie"] = cookie
                    flowDict["SourceIP"] = ip_src
                    flowDict["DestinationIP"] = ip_dst 
                    flowDict["tp_dst"] = f.match['tcp_dst']
                    flowDict["tp_src"] = f.match['tcp_src']
                    flowDict["Bytes"] = f.byte_count
                    flowDict["Duration"] = f.duration_sec
                    flowDict["RTime"] = 0
                    flowDict["RBytes"] = 0

                    self.usageDict[cookie] = flowDict

                    points.append({
                            "measurement": "volume",
                            "tags": tags,
                            "time": int(rcv_time),
                            "fields": {"value": float(f.byte_count) } })

                else:
                    flowDict = self.usageDict[cookie]

                    #only update if the count are different
                    if flowDict["Bytes"] != f.byte_count:

                        byteIncrement = f.byte_count - flowDict["Bytes"]
                        timeIncrement = int(rcv_time) - flowDict["Time"]

                        flowDict["Time"] = int(rcv_time)
                        flowDict["Bytes"] = f.byte_count
                        flowDict["Duration"] = f.duration_sec
                        flowDict["RTime"] = 0
                        flowDict["RBytes"] = 0

                        points.append({
                            "measurement": "volume",
                            "tags": tags,
                            "time": int(rcv_time),
                            "fields": {"value": float(f.byte_count) } })

                        points.append({
                            "measurement": "rate",
                            "tags": tags,
                            "time": int(rcv_time),
                            "fields": {"value": float(byteIncrement) } })

                        #avoid buffering time, mark byte count at 60s
                        if f.duration_sec > 60 and flowDict["RTime"] == 0:

                            flowDict["RTime"] = f.duration_sec
                            flowDict["RBytes"] = f.byte_count

                        self.usageDict[cookie] = flowDict


                        '''MBPS calculation'''
                        if ip_src not in self.calDict:
                            
                            entryDict = {}
                            #first entry
                            entryDict["Byte"] = byteIncrement;
                            entryDict["Time"] = int(rcv_time);
                            entryDict["TimePrevious"] = int(rcv_time);
                            entryDict["BytePrevious"] = byteIncrement;

                            dstDict = {}
                            dstDict[ip_dst] = entryDict
                            self.calDict[ip_src] = dstDict
                        else:
                            dstDict = self.calDict[ip_src]

                            if ip_dst not in dstDict:
                                entryDict = {}
                                #first entry
                                entryDict["Byte"] = byteIncrement;
                                entryDict["Time"] = int(rcv_time);
                                entryDict["TimePrevious"] = int(rcv_time);
                                entryDict["BytePrevious"] = byteIncrement;
                                dstDict[ip_dst] = entryDict
                            else:
                                entryDict = dstDict[ip_dst]
                                newByteCount = entryDict["Byte"] + byteIncrement;
                                entryDict["Byte"] = newByteCount 
                                entryDict["Time"] = int(rcv_time);

                                #if more than 10 sec from previous measurement
                                timeDiff = int(rcv_time) - entryDict["TimePrevious"]
                                if  timeDiff > 10:
                                    totalByteInc = float(newByteCount  - entryDict["BytePrevious"])
                                    Mbps = float(totalByteInc) * 8 / (timeDiff * 1024000)

                                    #reset previous record
                                    entryDict["TimePrevious"] = int(rcv_time);
                                    entryDict["BytePrevious"] = newByteCount;


                                    QualityStr = "???"
                                    if Mbps > 15:
                                        QualityStr = "???"
                                    elif Mbps > 10:
                                        QualityStr = "UHD"
                                    elif Mbps > 8:
                                        QualityStr = "UHD/HD"
                                    elif Mbps > 5:
                                        QualityStr = "HD"
                                    elif Mbps > 2:
                                        QualityStr = "HD/SD"
                                    elif Mbps > 0.3:
                                        QualityStr = "SD"
                                    else:
                                        QualityStr = "???"
                                        pass

                                    MbpsTags = {
                                                "dst_ip": ip_dst,
                                                "src_ip": ip_src,
                                                "src_port":f.match['tcp_src'],
                                                "Quality" :QualityStr,
                                                "Endpoint":endPointStr
                                        }

                                    #update Mbps measurement
                                    points.append({
                                        "measurement": "Mbps",
                                        "tags": MbpsTags,
                                        "time": int(rcv_time),
                                        "fields": {"value": float(Mbps) }} )

                #ship_points_to_influxdb(points)

            #ship_points_to_influxdb(testPoints)





