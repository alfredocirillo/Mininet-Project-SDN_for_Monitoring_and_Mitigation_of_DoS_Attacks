import threading

from stats_collector import Stats
from queue import Queue

import enum

# Codici di escape ANSI per i colori
RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

class Policy:
    '''
    To notify when there's a flow that needs to be blocked. Parameters are:\\
    - dpid = id of the datapath
    - eth_src = source host MAC
    - eth_dst = destination host MAC
    - need_block = boolean
    '''
    def __init__(self, dpid, eth_src, eth_dst, block_time, block:bool = True):
        super().__init__()
        self.dpid = dpid
        self.eth_src = eth_src
        self.eth_dst = eth_dst
        self.block_time = block_time
        self.block = block

BASE_TIME = 60 #sec

class PolicyMaker(threading.Thread):
    def __init__(self, controller, stats_queue, policy_queue, flow_alarm, treshold):
        '''
        Receives flow stats and makes blocks/unblocks based on traffic analysis
        '''
        super().__init__(daemon=True)
        self.controller = controller
        self.logger = self.controller.logger

        self.stats_q: Queue = stats_queue
        self.policy_q: Queue = policy_queue

        self.treshold = treshold #bytes/sec

        # For the flow blocking functions
        self.flow_stats = {}
        self.flow_alarm = flow_alarm

        self.logger.info('Policy Maker started')

    def run(self):
        while True:
            # Take stats from the queue
            ev: Stats = self.stats_q.get()
            dpid = ev.dpid
            collected_stats = ev.stats
            time_interval = ev.time_interval

            #print(f"Time: {time_interval}")

            # Filter flows
            flows = sorted(
                    (flow for flow in collected_stats if flow.priority == 1),
                    key = lambda flow:(
                            flow.match['in_port'], 
                            flow.match.get('eth_src'), 
                            flow.match.get('eth_dst')
                            )
                        )
            
            if len(flows) == 0:
                continue

            if(dpid not in self.flow_stats.keys()):
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
                                        f'{dpid:016x}',
                                        eth_src,
                                        eth_dst,
                                        in_port,
                                        stat.instructions[0].actions[0].port,
                                        stat.packet_count,
                                        (stat.byte_count/time_interval)
                                    )
                    
                # Inizializza contatore allarme
                self.flow_alarm[dpid]={
                    # [counter, state, threat_level] with values [ [1,3], {0, 1}, [0, 4] ]
                    (stat.match.get('eth_src'), stat.match.get('eth_dst')) : [0, 0, 0]
                    for stat in flows
                }

                # Aggiorna stats
                self.flow_stats[dpid] = {
                    (stat.match['in_port'], stat.match.get('eth_src'), stat.match.get('eth_dst')) : [stat.packet_count, stat.byte_count]
                    for stat in flows
                }
            else:
                self.logger.info('%-18s %-20s %-20s %-8s %-8s %-8s %-12s',
                                'Datapath', 'MAC_src', 'MAC_dst', 'Port_in', 'Port_out', 'Packets', 'Bytes/s'
                                )

                previous = self.flow_stats[dpid]

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
                                        f'{dpid:016x}',
                                        eth_src,
                                        eth_dst,
                                        in_port,
                                        stat.instructions[0].actions[0].port,
                                        packet_count,
                                        byte_diff / time_interval
                                    )
                    
                    # Inizializza contatore allarme se non inizializzato
                    if((eth_src, eth_dst) not in self.flow_alarm[dpid]):
                        self.flow_alarm[dpid][(eth_src, eth_dst)] = [0, 0, 0]    # add Threat to counter

                    # Alarm Management
                    if( (byte_diff/time_interval) > self.treshold): #quando il flusso supera il treshold
                        if(self.flow_alarm[dpid][(eth_src, eth_dst)][0] < 3):
                            self.flow_alarm[dpid][(eth_src, eth_dst)][0] += 1	#aumenta il contatore
                    else: # quando il flusso è nei limiti del treshold
                        if(self.flow_alarm[dpid][(eth_src, eth_dst)][0] > 0):
                            self.flow_alarm[dpid][(eth_src, eth_dst)][0] -= 1	#diminuisci il contatore

                    if(self.flow_alarm[dpid][(eth_src, eth_dst)][0] >= 3):
                        # Block time
                        threat_lvl = self.flow_alarm[dpid][(eth_src, eth_dst)][2]
                        block_time = BASE_TIME * (1 + threat_lvl) # 60, 120, 180, 240, 300 seconds

                        # Send block warning through queue
                        self.policy_q.put(Policy(dpid, eth_src, eth_dst, block_time))

                        # Raise Alarm State for the flow
                        self.flow_alarm[dpid][(eth_src, eth_dst)][1] = 1

                        # Update the flow's ThreatLevel
                        if self.flow_alarm[dpid][(eth_src, eth_dst)][2] < 4:
                            self.flow_alarm[dpid][(eth_src, eth_dst)][2] += 1

                # Aggiorna stats
                self.flow_stats[dpid] = {
                    (stat.match['in_port'], stat.match.get('eth_src'), stat.match.get('eth_dst')) : [stat.packet_count, stat.byte_count]
                    for stat in flows
                }