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
from ryu.controller import dpset
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

from flask import Flask
from flask.ext.cors import CORS



import threading

import time, os, random, json, datetime

from influxdb import InfluxDBClient

from ryu.app.wsgi import ControllerBase, WSGIApplication
import json
import logging
import ast
from webob import Response


LOG = logging.getLogger('ryu.app.ryu_nf4')
NOVI_DPID = 0x0000000000000064

# TODO: configurable
INFLUXDB_DB = "flowBucket"
INFLUXDB_HOST = "129.94.5.44"
INFLUXDB_PORT = 8086
INFLUXDB_USER = ""
INFLUXDB_PASS = ""


def ship_points_to_influxdb(points):
    client = InfluxDBClient(
        host=INFLUXDB_HOST, port=INFLUXDB_PORT,
        username=INFLUXDB_USER, password=INFLUXDB_PASS,
        database=INFLUXDB_DB, timeout=10)
    return client.write_points(points=points, time_precision='s')


transferDict = {}
reportAggDict = {}
react_cookie_offset = 0 

app  = Flask(__name__)
CORS(app)

@app.route('/')
def hello_world():
    global transferDict
    global reportAggDict

    outDict = {}
    mList = [];
    for ip_src in transferDict:

        srcDict = transferDict[ip_src]
        for ip_dst in srcDict:
            entryDict = srcDict[ip_dst]

            #only report if it has significant traffics
            if (entryDict["isVideo"]):

                newDict = {}
                newDict["time"] = entryDict["Time"]
                newDict["srcIp"] = ip_src
                newDict["dstIp"] = ip_dst
                newDict["beginTime"] = entryDict["BeginTime"]
                newDict["duration"] =entryDict["Duration"]
                newDict["byte"] = entryDict["Byte"]

                if "Endpoint" in entryDict:
                  newDict["endpoint"] =  entryDict["Endpoint"] 

                if "Mbps" in entryDict:
                  newDict["mbps"] = entryDict["Mbps"]
                if "Quality" in entryDict:
                  newDict["quality"]= entryDict["Quality"]
                mList.append(newDict)

        outDict["flows"] = mList;

    aggDict = {}
    aggDict["totalBytes"] = reportAggDict["Default_byte_count"] + reportAggDict["Total_NF_count"] 
    aggDict["netflixBytes"] = reportAggDict["Total_NF_count"]
    aggDict["time"] = reportAggDict["Time"]
    outDict["usage"] = aggDict

    return json.dumps(outDict)


class NFReactiveController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(NFReactiveController, self).__init__(req, link, data, **config)
        self.dpset = data['dpset']
        self.waiters = data['waiters']

        self.gatewayPort = 24 #pica 8
        self.clientPort = 26 #uniwideSDN
        self.mirrorPort = 22



    def get_dpids(self, req, **_kwargs):
        LOG.debug('get_dpids')
        dps = list(self.dpset.dps.keys())
        body = json.dumps(dps)
        return Response(content_type='application/json', body=body)

    def netfilx_reactive_flow_mod(self,dp,srcIP,dstIP,src_port,dst_port):

        global react_cookie_offset
        match = parser.OFPMatch(ipv4_src=srcIP,ipv4_dst=dstIP,in_port=self.gatewayPort,tcp_src = src_port, tcp_dst = dst_port)
        # self.logger.info("after ofpmatch")
        priority = 20000
        idle_timeout = 60

        # TODO change instruction 

        action1 = parser.OFPActionOutput(self.clientPort);
        actionController = parser.OFPActionOutput(ofp.OFPP_CONTROLLER);
        actions = [action1]
        # self.logger.info("after actions")
        # self.logger.info("dp: %s, srcIp: %s match: %s priority: %s actions: %s", datapath, src_ip, match, priority, actions)
        
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                             actions)]
        # self.logger.info("after inst")
        
        mod = parser.OFPFlowMod(datapath=dp, cookie= (0x47470000 + int((time.time())*100000)) ,  priority=priority, table_id = 0, 
                                match=match, command=ofp.OFPFC_ADD, instructions=inst, hard_timeout=0,
                                idle_timeout=idle_timeout,
                                flags=ofp.OFPFF_SEND_FLOW_REM)

        react_cookie_offset = react_cookie_offset + 1
        
        return mod

    def add_reactive_flow(self, req, cmd, **_kwargs):
        LOG.debug('add_reactive_flow')
        

        try:
            data = ast.literal_eval(req.body)

            dpid = data.get('dpid')
            ip_dst = data.get('ip_dst')
            port_dst = data.get('port_dst')
            ip_src = data.get('ip_src')
            port_src = data.get('port_src')

        except SyntaxError:
            LOG.debug('invalid syntax %s', req.body)
            return Response(status=400)

        if type(dpid) == str and not dpid.isdigit():
            LOG.debug('invalid dpid %s', dpid)
            return Response(status=400)

        dp = self.dpset.get(int(dpid))

        if dp is None:
            return Response(status=404)

        LOG.debug(ip_dst)
        LOG.debug(port_dst)
        LOG.debug(ip_src)
        LOG.debug(port_src)

        dp.send_msg(self.netfilx_reactive_flow_mod(dp,ip_src,ip_dst,port_src,port_dst))

        return Response(status=200)



ryuNFApp = 0;

'''RYU stuff'''

class ryu_nf4(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'dpset': dpset.DPSet,
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(ryu_nf4, self).__init__(*args, **kwargs)
        global ryuNFApp 
        ryuNFApp = self
        self.datapaths = {}
        self.logger.debug("Init");

        #our internal record fpr stat
        self.usageDict = {} #raw info with port level stat
        self.calDict = {} #byte count, IP level
        self.aggreatedUsage = {}
        self.aggreatedUsage["Total_NF_count"] = 0;
        self.aggreatedUsage["Default_byte_count"] = 0;
        self.aggreatedUsage["Time"] = 0;
        self.aggreatedUsage["active"] = 0;


        self.gatewayPort = 24 #pica 8
        self.clientPort = 26 #uniwideSDN
        self.mirrorPort = 22

        #runServer()
        #self.logger.debug("Start BC ");
        #self.bc = Connection("127.0.0.1:47758")

        self.flask_thread= hub.spawn(self._runServer)
        self.monitor_thread = hub.spawn(self._monitor)

        self.dpset = kwargs['dpset']
        wsgi = kwargs['wsgi']
        self.waiters = {}
        self.data = {}
        self.data['dpset'] = self.dpset
        self.data['waiters'] = self.waiters
        mapper = wsgi.mapper

        wsgi.registory['NFReactiveController'] = self.data
        path = '/stats'
        uri = path + '/switches'
        mapper.connect('stats', uri,
                       controller=NFReactiveController, action='get_dpids',
                       conditions=dict(method=['GET']))

        path = '/reacts'
        uri = path + '/add/{cmd}'
        mapper.connect('stats', uri,
                       controller=NFReactiveController, action='add_reactive_flow',
                       conditions=dict(method=['POST']))

    def _runServer(self):
        self.logger.debug("Start Serv");
        app.run(host='0.0.0.0')

    def _monitor(self):

        while True:
            #self.bc.processInput();
            self.logger.debug("Monitor");
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
        

        cookie_offset = 0
        for netflix_srcc in netflix_src_list:
            # self.logger.info("initiating and inserting netflix src flow entry: %s", netflix_srcc)
            netflix_src=netflix_srcc.strip()

            flowmods = self.netflix_flows_mod(datapath, netflix_src,cookie_offset)
            cookie_offset +=1
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

        priority = 100

        #server -> client
        match = parser.OFPMatch(in_port=self.gatewayPort)

        action1 = parser.OFPActionOutput(self.clientPort,0);
        actions = [action1]

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, cookie=0x44,  priority=priority, table_id = 0, 
                                match=match, command=ofp.OFPFC_ADD, instructions=inst, hard_timeout=0,
                                idle_timeout=0,
                                flags=ofp.OFPFF_SEND_FLOW_REM)
        datapath.send_msg(mod);



        #Client -> Server 
        match = parser.OFPMatch(in_port=self.clientPort)

        action1 = parser.OFPActionOutput(self.gatewayPort,0);
        actions = [action1]

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, cookie=0x45,  priority=priority, table_id = 0, 
                                match=match, command=ofp.OFPFC_ADD, instructions=inst, hard_timeout=0,
                                idle_timeout=0,
                                flags=ofp.OFPFF_SEND_FLOW_REM)
        datapath.send_msg(mod);


    def netflix_flows_mod(self,dp, netflix_src,cookie_offset):
        datapath = dp

        parser = datapath.ofproto_parser

        src_ip = netflix_src
        part=src_ip.split("/")
        ip=part[0]
        self.logger.info(ip)

        mask="255.255.255.0"

        match = parser.OFPMatch(ipv4_src=(ip,mask)) #eth_type = 0x0800,
        # self.logger.info("after ofpmatch")
        priority = 10000

        # TODO change instruction 

        action1 = parser.OFPActionOutput(self.clientPort);
        action2 = parser.OFPActionOutput(self.mirrorPort);
        actionController = parser.OFPActionOutput(ofp.OFPP_CONTROLLER);
        actions = [action1,action2 ] #
        #actions = [action1 ] #
        # self.logger.info("after actions")
        # self.logger.info("dp: %s, srcIp: %s match: %s priority: %s actions: %s", datapath, src_ip, match, priority, actions)
        
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                             actions)]
        # self.logger.info("after inst")
        
        mod = parser.OFPFlowMod(datapath=datapath, cookie=(0x3309 + cookie_offset),  priority=priority, table_id = 0, 
                                match=match, command=ofp.OFPFC_ADD, instructions=inst, hard_timeout=0,
                                idle_timeout=0,
                                flags=ofp.OFPFF_SEND_FLOW_REM)
        return mod


    ''' stat event handler'''
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        global transferDict
        global reportAggDict
        rcv_time = time.time()
        msg = ev.msg
        body = msg.body


        self.logger.info("Flow Stat received");

        
        fTable2 = [flow for flow in body if (flow.cookie == 0x44 and flow.priority == 100)];
        self.logger.info("Size2: " +str(len(fTable2)));

        for f in fTable2:
            dpid  = msg.datapath.id
            cookie = f.cookie
            packet_count = f.packet_count
            byte_count = f.byte_count

            self.logger.info('cookie:%d byte_count: %d', cookie,byte_count);

            self.aggreatedUsage["Default_byte_count"] = byte_count
            self.aggreatedUsage["Time"] = int(rcv_time)



        fTable = [flow for flow in body if (flow.priority == 20000 and flow.table_id == 0 and flow.byte_count > 0)]; #and flow.byte_count > 0
         #and flow.byte_count > 0

        self.logger.info("Size1: " +str(len(fTable)));


        points = [] #for influx 

        #[flow for flow in body if (flow.priority == 20000 and flow.table_id == 0)]
        for f in fTable:
            #for f in [flow for flow in body]:

            dpid  = msg.datapath.id
            cookie = f.cookie
            packet_count = f.packet_count
            byte_count = f.byte_count
            

            '''influx stuff'''
            
             #process raw info and push to Influx DB
            #TODO: more processing
            

            self.logger.info('cookie:%d byte_count: %d', cookie,byte_count);

            ip_src = str(f.match['ipv4_src'])
            ip_dst = str(f.match['ipv4_dst'])

           
            if(f.match['tcp_src'] == 80):
                endPointStr = "mobile"
            else:
                endPointStr = "web browser"

            tags = {
                    "dpid": dpid, #int16
                    "dst_ip": ip_dst,
                    "src_ip": ip_src,
                    "src_port":f.match['tcp_src'],
                    "dst_port":f.match['tcp_dst'],
                    "flow_id":cookie,
                    "attribute_provider":"Optus",
                    "attribute_user":endPointStr,
                    "attribute_others":"NF"
                    }

            #append point to influx Entry
            points.append({
                "measurement": "flowStat",
                "tags": tags,
                "time": int(rcv_time),
                "fields": {
                    "byte_count": int(f.byte_count),
                    "packet_count": int(f.packet_count),
                    "duration": int(f.duration_sec)
                 }
                  })


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


            else:
                flowDict = self.usageDict[cookie]

                byteIncrement = f.byte_count - flowDict["Bytes"]
                timeIncrement = int(rcv_time) - flowDict["Time"]

                if(byteIncrement < 0):
                    self.logger.info("!!! HEY its negative!");
                    self.logger.info("Counts: %d %d",f.byte_count , flowDict["Bytes"]);
                    self.logger.info("Time: %d %d", int(rcv_time) , flowDict["Time"]);
                    self.logger.info("cookie: %d %d", cookie, f.cookie);
                    self.logger.info("port: %s %s", flowDict["tp_dst"], f.match['tcp_dst']);
                    raise ValueError('!!! HEY its negative!')

                    continue;

                #add increment to total NF counter
                self.aggreatedUsage["Total_NF_count"] += byteIncrement;

                flowDict["Time"] = int(rcv_time)
                flowDict["Bytes"] = f.byte_count
                flowDict["Duration"] = f.duration_sec
                flowDict["RTime"] = 0
                flowDict["RBytes"] = 0

                #avoid buffering time, mark byte count at 60s
                if f.duration_sec > 60 and flowDict["RTime"] == 0:

                    flowDict["RTime"] = f.duration_sec
                    flowDict["RBytes"] = f.byte_count

                self.usageDict[cookie] = flowDict

                #calDict is IP level stat keeping
                '''MBPS calculation'''
                if ip_src not in self.calDict:

                    #first seen, but 0 byte
                    if byteIncrement == 0:
                        continue

                    #first entry
                    entryDict = {}
                    entryDict["Byte"] = byteIncrement;
                    entryDict["Time"] = int(rcv_time);
                    entryDict["BeginTime"] = int(rcv_time); # time first receive IP pairs
                    entryDict["Duration"] = 0
                    entryDict["TimePrevious"] = int(rcv_time);
                    entryDict["BytePrevious"] = byteIncrement;
                    entryDict["TimePrevious2"] = int(rcv_time);
                    entryDict["BytePrevious2"] = byteIncrement;
                    entryDict["Endpoint"] = endPointStr
                    entryDict["isVideo"] = False;

                    dstDict = {}
                    dstDict[ip_dst] = entryDict
                    self.calDict[ip_src] = dstDict

                else:
                    dstDict = self.calDict[ip_src]

                    if ip_dst not in dstDict:
                        
                        #first seen, but 0 byte
                        if byteIncrement == 0:
                            continue

                        #first entry
                        entryDict = {}
                        entryDict["Byte"] = byteIncrement;
                        entryDict["Time"] = int(rcv_time);
                        entryDict["BeginTime"] = int(rcv_time); # time first receive IP pairs
                        entryDict["Duration"] = 0
                        entryDict["TimePrevious"] = int(rcv_time);
                        entryDict["BytePrevious"] = byteIncrement;
                        entryDict["TimePrevious2"] = int(rcv_time);
                        entryDict["BytePrevious2"] = byteIncrement;
                        entryDict["Endpoint"] = endPointStr
                        entryDict["isVideo"] = False;
                        dstDict[ip_dst] = entryDict

                    else:

                        entryDict = dstDict[ip_dst]
                        newByteCount = entryDict["Byte"] + byteIncrement;

                        entryDict["Byte"] = newByteCount 
                        entryDict["Time"] = int(rcv_time);
                        entryDict["Duration"] = int(rcv_time) - entryDict["BeginTime"];

                        flowMbps = float(entryDict["Byte"]) * 8 / (entryDict["Duration"]  * 1024 * 1024);
                        if (flowMbps > 0.5):
                            entryDict["isVideo"] = True;
                        elif (flowMbps < 0.3):
                            entryDict["isVideo"] = False;

                        timeDiff = int(rcv_time) - entryDict["TimePrevious2"]
                        totalByteInc = newByteCount  - entryDict["BytePrevious2"]

                        if timeDiff > 35:

                            #reset previous record
                            entryDict["TimePrevious2"] = int(rcv_time);
                            entryDict["BytePrevious2"] = newByteCount;

                            if entryDict["Duration"] > 70:
                                Mbps = float(totalByteInc) * 8 / (timeDiff  * 1024 * 1024)
                                entryDict["Mbps"] = Mbps

                                '''
                                if "Mbps" in entryDict:
                                    entryDict["Mbps"] = Mbps * (0.8) + entryDict["Mbps"] * 0.2 
                                else:
                                    entryDict["Mbps"] = Mbps
                                '''

                                QualityStr = "???"
                                if Mbps > 30:
                                    QualityStr = "???"
                                elif Mbps > 15:
                                    QualityStr = "UHD"
                                    entryDict["Quality"] = QualityStr
                                elif Mbps > 4:
                                    QualityStr = "HD"
                                    entryDict["Quality"] = QualityStr
                                elif Mbps > 1:
                                    QualityStr = "SD"
                                    entryDict["Quality"] = QualityStr
                                elif Mbps > 0.5:
                                    QualityStr = "LOW"
                                    entryDict["Quality"] = QualityStr
                                else:
                                    pass


                        #for idle flow deletion
                        timeDiff = int(rcv_time) - entryDict["TimePrevious"]
                        totalByteInc = newByteCount  - entryDict["BytePrevious"]

                        #if more than 15 sec from previous measurement
                        if timeDiff > 15 :
                            #reset previous record
                            entryDict["TimePrevious"] = int(rcv_time);
                            entryDict["BytePrevious"] = newByteCount;

                            if totalByteInc != 0:
                                pass

                            else:
                                #no traffic in previous 15 sec
                                del dstDict[ip_dst]
                                self.calDict[ip_src] = dstDict


        if points:
            ship_points_to_influxdb(points)

        #ship_points_to_influxdb(testPoints)
        transferDict = self.calDict
        reportAggDict = self.aggreatedUsage





