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
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import hub
import time

timeInterval = 10

# Codici di escape ANSI per i colori
RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"


class SimpleSwitch13(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	global timeInterval
	global RED
	global RESET
	global GREEN 

	def __init__(self, *args, **kwargs):
		super(SimpleSwitch13, self).__init__(*args, **kwargs)
		self.send_req = 0
		self.rec_res = 0
		self.threshold = 700000 #80-90% del percorso critico
		self.time = 0
		self.datapaths = {}
		self.mac_to_port = {}

		self.monitor_thread = hub.spawn(self._monitor)
  
		self.flow_stats = {}
		self.flow_alarm = {}

# MONITORING

	# Funzione di aggiunta e rimozione switch dalla struttura datapath
	@set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
	def _state_change_handler(self, ev):
		datapath = ev.datapath
		if ev.state == MAIN_DISPATCHER:
			if datapath.id not in self.datapaths:
				self.logger.debug('register datapath: %016x', datapath.id)
				self.datapaths[datapath.id] = datapath
		elif ev.state == DEAD_DISPATCHER:
			if datapath.id in self.datapaths:
				self.logger.debug('unregister datapath: %016x', datapath.id)
				del self.datapaths[datapath.id]

	# Funzione di richiesta delle stats agli switch
	def _request_stats(self, datapath):
		self.logger.debug('send stats request: %016x', datapath.id)
		parser = datapath.ofproto_parser

		req = parser.OFPFlowStatsRequest(datapath)
		datapath.send_msg(req)
		self.send_req = time.perf_counter()

	# Funzione di monitoraggio sempre attiva, ogni 10 secondi chiede a ogni switch di
	# inviare le sue stats di ogni porta
	def _monitor(self):
		while True:
			for dp in self.datapaths.values():
				self._request_stats(dp)
			self.logger.info('\n#########################################################')
			hub.sleep(timeInterval)

	# Handler per la ricezione delle statistiche di flow
	@set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
	def _flow_stats_reply_handler(self, ev):
		body = ev.msg.body
		self.rec_res = time.perf_counter()
  
  		# Intervallo calcolato come 10 + differenza tra tempo di richiesta e risposta delle stats
		self.time = timeInterval + (self.rec_res - self.send_req)
		print(f"Time: {self.time}")

		# Filter flows
		flows = sorted(
				(flow for flow in body if flow.priority == 1),
				key = lambda flow:(
						flow.match['in_port'], 
						flow.match.get('eth_src'), 
						flow.match.get('eth_dst')
						)
					)
		
		if len(flows) == 0:
			return


		dp = ev.msg.datapath

		if(dp.id not in self.flow_stats.keys()):
			self.logger.info('%-18s %-20s %-20s %-8s %-8s %-8s %-12s',
							'Datapath', 'MAC_src', 'MAC_dst', 'Port_in', 'Port_out', 'Packets', 'Bytes/s'
							)
			
			for stat in flows:
				eth_src = stat.match.get('eth_src'),
				eth_src = eth_src[0] if eth_src[0] else 'N/A'

				eth_dst = stat.match.get('eth_dst'),
				eth_dst = eth_dst[0] if eth_dst[0] else 'N/A'

				in_port = stat.match['in_port']
				in_port = in_port if isinstance(in_port, int) else in_port[0]
				
				self.logger.info('%-18s %-20s %-20s %8d %8d %8d %10.2f',
									f'{dp.id:016x}',
									eth_src,
									eth_dst,
									in_port,
									stat.instructions[0].actions[0].port,
									stat.packet_count,
									(stat.byte_count/self.time)
								)
				
			# Inizializza contatore allarme
			self.flow_alarm[dp.id]={
				(stat.match['in_port'], stat.match.get('eth_src'), stat.match.get('eth_dst')) : [0, 0]
				for stat in flows
			}

			# Aggiorna stats
			self.flow_stats[dp.id] = {
				(stat.match['in_port'], stat.match.get('eth_src'), stat.match.get('eth_dst')) : [stat.packet_count, stat.byte_count]
				for stat in flows
			}
		else:
			self.logger.info('%-18s %-20s %-20s %-8s %-8s %-8s %-12s',
							'Datapath', 'MAC_src', 'MAC_dst', 'Port_in', 'Port_out', 'Packets', 'Bytes/s'
							)

			previous = self.flow_stats[dp.id]

			for stat in flows:
				eth_src = stat.match.get('eth_src'),
				eth_src = eth_src[0] if eth_src[0] else 'N/A'

				eth_dst = stat.match.get('eth_dst'),
				eth_dst = eth_dst[0] if eth_dst[0] else 'N/A'

				in_port = stat.match['in_port']
				in_port = in_port if isinstance(in_port, int) else in_port[0]

				packet_count = stat.packet_count - previous.get((in_port, eth_src, eth_dst), [0,0])[0]
				byte_diff = stat.byte_count - previous.get((in_port, eth_src, eth_dst), [0,0])[1]

				self.logger.info('%-18s %-20s %-20s %8d %8d %8d %10.2f',
									f'{dp.id:016x}',
									eth_src,
									eth_dst,
									in_port,
									stat.instructions[0].actions[0].port,
									packet_count,
									byte_diff / self.time
								)
				
				# Inizializza contatore allarme
				if((in_port, eth_src, eth_dst) not in self.flow_alarm[dp.id]):
					self.flow_alarm[dp.id][(in_port, eth_src, eth_dst)] = [0,0]

				# Alarm Management
				if( (byte_diff/self.time) > self.threshold): #quando il flusso supera il treshold
					if(self.flow_alarm[dp.id][(in_port, eth_src, eth_dst)][0] < 3):
						self.flow_alarm[dp.id][(in_port, eth_src, eth_dst)][0] += 1	#aumenta il contatore
				else: # quando il flusso è nei limiti del treshold
					if(self.flow_alarm[dp.id][(in_port, eth_src, eth_dst)][0] > 0):
						self.flow_alarm[dp.id][(in_port, eth_src, eth_dst)][0] -= 1	#diminuisci il contatore

				if(self.flow_alarm[dp.id][(in_port, eth_src, eth_dst)][0] >= 3):
					self.lock_flow(ev, eth_src, eth_dst, in_port)
				elif(self.flow_alarm[dp.id][(in_port, eth_src, eth_dst)][0] == 2 and self.flow_alarm[dp.id][(in_port, eth_src, eth_dst)][1] == 1):
					self.logger.info(GREEN + f"Flusso da {eth_src} a {eth_dst} in switch {dp.id} RIPRISTINATO")
					# Reset the alarmed state for the flow
					self.flow_alarm[dp.id][(in_port, eth_src, eth_dst)][1] == 0

			# Aggiorna stats
			self.flow_stats[dp.id] = {
				(stat.match['in_port'], stat.match.get('eth_src'), stat.match.get('eth_dst')) : [stat.packet_count, stat.byte_count]
				for stat in flows
			}
			
	# Remediation per l'allarme
	def lock_flow(self, ev, eth_src, eth_dst, in_port):	
		ofproto = ev.msg.datapath.ofproto
		parser = ev.msg.datapath.ofproto_parser
		
		match = parser.OFPMatch(eth_src = eth_src, eth_dst = eth_dst)
		
		instructions=[]
		
		flow_mod = parser.OFPFlowMod(datapath=ev.msg.datapath, 
									priority=2, 
									match=match, 
									instructions=instructions, 
									command=ofproto.OFPFC_ADD,
									idle_timeout = 60,	# La regola scade dopo Xs di idle
									out_port=ofproto.OFPP_ANY, 
									out_group=ofproto.OFPG_ANY, 
									flags=ofproto.OFPFF_SEND_FLOW_REM )
		
		ev.msg.datapath.send_msg(flow_mod)
		print(RED + f"Flusso da Host {eth_src} ad Host {eth_dst} per lo switch {ev.msg.datapath.id} BLOCCATO" + RESET)

		# Set the alarmed state for the flow
		self.flow_alarm[ev.msg.datapath.id][(in_port, eth_src, eth_dst)][1] == 1 

	
		
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

