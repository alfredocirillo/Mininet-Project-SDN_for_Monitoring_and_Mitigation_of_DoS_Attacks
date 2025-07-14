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

from operator import attrgetter
from queue import Queue
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

# Self-made Classes
from blocklist import Blocklist
from policy_enforcer import PolicyEnforcer
from policy_maker import PolicyMaker
from stats_collector import StatsCollector, Stats

import time

# Codici di escape ANSI per i colori
RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"


class SimpleSwitch13(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	global RED
	global RESET
	global GREEN 

	def __init__(self, *args, **kwargs):
		super(SimpleSwitch13, self).__init__(*args, **kwargs)
		self.datapaths = {}
		self.mac_to_port = {}

		# Queues 
		self.stats_queue = Queue()
		self.policy_queue = Queue()

		# Blocklist
		self.blocklist = Blocklist(filename = 'blocked.json')

		self.flow_alarm = {}

		# Classes for modularity
		self.collector = StatsCollector(self, sleep_time = 5)
		self.policy_maker = PolicyMaker(self, self.stats_queue, self.policy_queue, self.flow_alarm, treshold=65000)
		self.policy_enforcer = PolicyEnforcer(self, self.policy_queue, self.blocklist)

		self.collector.start()
		self.policy_maker.start()
		self.policy_enforcer.start()

	# To receive the flow stats requested by the self.collector thread
	@set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
	def _flow_stats_reply_handler(self, ev):
		dpid = ev.msg.datapath.id
		stats = ev.msg.body

		req_time = self.collector.req_time
		rec_res = time.perf_counter()
		time_interval = 10 + (rec_res - req_time)

		# Notifies observers that stats have been collected
		# In this case the only observer is the policy_maker
		self.stats_queue.put(Stats(dpid, stats, time_interval))

	# To remove the flow entry from the blocklist once timer expires
	@set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
	def _flow_timeout_handler(self, ev):
		msg = ev.msg
		dp = msg.datapath
		ofp = dp.ofproto

		if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
			dpid = dp.id

			match = msg.match # instance of OSPFMatch used
			eth_src = match.get('eth_src')
			eth_dst = match.get('eth_dst')
			self.blocklist.remove(dpid, eth_src, eth_dst)
			self.flow_alarm[dpid][(eth_src, eth_dst)][1] = 0 # reset alarm state

			self.logger.info(GREEN + f"Block Policy for flow from {eth_src} to {eth_dst} through switch {dpid} has expired" + RESET)
			

	# Funzione di aggiunta e rimozione switch dalla struttura datapath
	@set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
	def _state_change_handler(self, ev):
		datapath = ev.datapath

		if ev.state == MAIN_DISPATCHER:
			if datapath.id not in self.datapaths:
				self.logger.debug('Connected datapath: %016x', datapath.id)
				self.datapaths[datapath.id] = datapath
		elif ev.state == DEAD_DISPATCHER:
			if datapath.id in self.datapaths:
				self.logger.debug('Disconnected datapath: %016x', datapath.id)
				del self.datapaths[datapath.id]


# Configurazione / Codice già fornito
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions)

	def add_flow(self, datapath, priority, match, actions, buffer_id=None):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
		if buffer_id:
			mod = parser.OFPFlowMod(datapath=datapath, 
									buffer_id=buffer_id,
									priority=priority, 
									match=match,
									instructions=inst) 
		else:
			mod = parser.OFPFlowMod(datapath=datapath, 
									priority=priority,
									match=match, 
									instructions=inst)
		datapath.send_msg(mod)

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		if ev.msg.msg_len < ev.msg.total_len:
			self.logger.debug("packet truncated: only %s of %s bytes",
							ev.msg.msg_len, ev.msg.total_len)
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		in_port = msg.match['in_port']

		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]

		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
			return
		dst = eth.dst
		src = eth.src

		dpid = datapath.id
		self.mac_to_port.setdefault(dpid, {})

		self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

		self.mac_to_port[dpid][src] = in_port

		if dst in self.mac_to_port[dpid]:
			out_port = self.mac_to_port[dpid][dst]
		else:
			out_port = ofproto.OFPP_FLOOD

		actions = [parser.OFPActionOutput(out_port)]

		if out_port != ofproto.OFPP_FLOOD:
			match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
			if msg.buffer_id != ofproto.OFP_NO_BUFFER:
				self.add_flow(datapath, 1, match, actions, msg.buffer_id)
				return
			else:
				self.add_flow(datapath, 1, match, actions)
		data = None
		if msg.buffer_id == ofproto.OFP_NO_BUFFER:
			data = msg.data

		out = parser.OFPPacketOut(datapath=datapath, 
									buffer_id=msg.buffer_id,
									in_port=in_port, 
									actions=actions, 
									data=data)
		datapath.send_msg(out)