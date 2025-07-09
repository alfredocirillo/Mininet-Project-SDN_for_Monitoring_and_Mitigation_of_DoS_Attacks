import threading, time

class Stats:
    '''
    To send the collected stats back to main.
    Parameters are \\
        - dpid = id of the datapath \\
        - stats = the collected stats \\
        - req_time = time when the request was made
    '''
    def __init__(self, dpid, stats, time_interval):
        super().__init__()
        self.dpid = dpid
        self.stats = stats
        self.time_interval = time_interval

class StatsCollector(threading.Thread):
    def __init__(self, controller, sleep_time = 10):
        '''
        Periodically gathers flows' stats
        '''
        super().__init__(daemon=True)
        self.controller = controller
        self.logger = self.controller.logger
        self.sleep_time = sleep_time

        self.req_time = 0

        print("Stats Collector Started")

    def run(self):
        while True:
            for dp in list(self.controller.datapaths.values()):
                req = dp.ofproto_parser.OFPFlowStatsRequest(dp)
                dp.send_msg(req)
                self.req_time = time.perf_counter()

            self.logger.info('\n#########################################################')
            time.sleep(self.sleep_time)        