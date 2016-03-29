from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet


class NF1(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    servList = []

    def __init__(self, *args, **kwargs):
        super(NF1, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        servListRAW = tuple(open('./Netflix_AS2906', 'r'))
        counter = 1000
        for i in servListRAW:
            self.servList.append(i.strip())
            self.logger.info("List Added: %s", i.strip())


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info("switch_features_handler: %s",datapath)

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions,10)


        #TODO: add default flow

        match = parser.OFPMatch(in_port=1)
        priority = 3000
        out_port = 3
        actions = [parser.OFPActionOutput(out_port)]
        self.add_flow(datapath, 0, match, actions,10)

        match = parser.OFPMatch(in_port=3)
        priority = 3000
        out_port = 1
        actions = [parser.OFPActionOutput(out_port)]
        self.add_flow(datapath, 0, match, actions,cookie = 10)


        #TODO: add netflix flows
        counter = 1000
        for NFEndPoint in self.servList:
            match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,ipv4_src=NFEndPoint)
            #send to controller if match
            priority = 5000
            cookie = counter
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)] 
            self.add_flow(datapath, 0, match, actions,cookie = 10)
            counter = counter +1 


    def add_flow(self, datapath, priority, match, actions,cookie):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst,cookie= cookie)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)


    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        out_port =3

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions,0)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)


        #TODO: install new individual stat flow


