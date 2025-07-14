from policy_maker import Policy
from blocklist import Blocklist

import threading, time
from queue import Queue

# Codici di escape ANSI per i colori
RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

class PolicyEnforcer(threading.Thread):
    def __init__(self, controller, policy_queue:Queue, blocklist:Blocklist):
        '''
        Receives policy and enforces it
        '''
        super().__init__(daemon=True)
        self.controller = controller
        self.logger = self.controller.logger
        self.policy_q: Queue = policy_queue
        self.blocklist: Blocklist = blocklist

    def run(self):
        # Load blocklist and enforce it
        # At startup the blocklist will contain only the admin-enforced blocks
        # These blocks are permanent
        while not self.controller.datapaths:
            time.sleep(3)
            
        for obj in self.blocklist.values():
            dpid = obj[0]
            src = obj[1]
            dst = obj[2] if obj[1] else None

            dp = self.controller.datapaths.get(dpid)
            parser = dp.ofproto_parser
            ofp = dp.ofproto

            if dst:
                match = parser.OFPMatch(eth_src = src, eth_dst = dst)
                self.logger.info(RED + f"Flow from {src} to {dst} through switch {dpid} blocked from file" + RESET)
            else:
                match = parser.OFPMatch(eth_src = src)
                self.logger.info(RED + f"All flows from {src} through switch {dpid} blocked from file" + RESET)
            
            mod = parser.OFPFlowMod(
                datapath=dp,
                priority=1000,
                match=match,
                instructions=[],
                command=ofp.OFPFC_ADD
            )
            dp.send_msg(mod)

        while True:
            ev: Policy = self.policy_q.get()
            dpid = ev.dpid
            src = ev.eth_src
            dst = ev.eth_dst
            block_time = ev.block_time

            # Avoid modifying policies set from external agents
            if (dpid, src, dst) in self.blocklist.ext_blocked:
                continue

            dp = self.controller.datapaths.get(dpid)
            if not dp:
                continue

            parser = dp.ofproto_parser
            ofp = dp.ofproto
            match = parser.OFPMatch(eth_src = src, eth_dst = dst)

            
            self.logger.info(RED + f"Flow from {src} to {dst} through switch {dpid} blocked" + RESET)
            mod = parser.OFPFlowMod(
                datapath=dp,
                priority=1000,
                match=match,
                instructions=[],
                idle_timeout = block_time,
                command = ofp.OFPFC_ADD,
                flags = ofp.OFPFF_SEND_FLOW_REM #to alert controller once mod expires
            )

            self.blocklist.add(dpid, src, dst)

            dp.send_msg(mod)