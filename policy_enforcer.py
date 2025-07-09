from policy_maker import Policy

import threading
from queue import Queue

# Codici di escape ANSI per i colori
RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

class PolicyEnforcer(threading.Thread):
    def __init__(self, controller, policy_queue):
        '''
        Receives policy and enforces it
        '''
        super().__init__(daemon=True)
        self.controller = controller
        self.logger = self.controller.logger
        self.policy_q: Queue = policy_queue

    def run(self):
        while True:
            ev: Policy = self.policy_q.get()
            dpid = ev.dpid
            eth_src = ev.eth_src
            eth_dst = ev.eth_dst
            block = ev.block

            dp = self.controller.datapaths.get(dpid)
            if not dp:
                continue

            parser = dp.ofproto_parser
            ofp = dp.ofproto
            match = parser.OFPMatch(eth_src = eth_src, eth_dst = eth_dst)

            if block:
                self.logger.info(RED + f"Flusso da {eth_src} a {eth_dst} in switch {dpid} bloccato" + RESET)
                mod = parser.OFPFlowMod(
                    datapath=dp,
                    priority=1000,
                    match=match,
                    instructions=[],
                    command=ofp.OFPFC_ADD
                )
            else:
                self.logger.info(GREEN + f"Flusso da {eth_src} a {eth_dst} in switch {dpid} ripristinato" + RESET)
                mod = parser.OFPFlowMod(
                    datapath=dp,
                    priority=1000,
                    match=match,
                    command=ofp.OFPFC_DELETE,
                    out_port=ofp.OFPP_ANY,
                    out_group=ofp.OFPG_ANY
                )

            dp.send_msg(mod)