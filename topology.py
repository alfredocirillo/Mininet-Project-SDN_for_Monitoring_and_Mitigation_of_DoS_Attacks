#!/usr/bin/python
import threading
import random
import time
from mininet.log import setLogLevel, info
from mininet.topo import Topo
from mininet.net import Mininet, CLI
from mininet.node import OVSKernelSwitch, Host
from mininet.link import TCLink, Link
from mininet.node import RemoteController #Controller

class Environment(object):

    def __init__(self):
        "Create a network."
        self.net = Mininet(controller=RemoteController, link=TCLink)
        info("*** Starting controller\n")
        c1 = self.net.addController( 'c1', controller=RemoteController) #Controller
        c1.start()
        
        # Hosts
        info("*** Adding hosts and switches\n")
        self.h1 = self.net.addHost('h1', mac='00:00:00:00:00:01', ip= '10.0.0.1')
        self.h2 = self.net.addHost('h2', mac='00:00:00:00:00:02', ip= '10.0.0.2')
        self.h3 = self.net.addHost('h3', mac='00:00:00:00:00:03', ip= '10.0.0.3')

        self.h4 = self.net.addHost('h4', mac='00:00:00:00:00:04', ip= '10.0.0.4')
        self.h5 = self.net.addHost('h5', mac='00:00:00:00:00:05', ip= '10.0.0.5')
        self.h6 = self.net.addHost('h6', mac='00:00:00:00:00:06', ip= '10.0.0.6')

        self.h7 = self.net.addHost('h7', mac='00:00:00:00:00:07', ip= '10.0.0.7')
        self.h8 = self.net.addHost('h8', mac='00:00:00:00:00:08', ip= '10.0.0.8')
        self.h9 = self.net.addHost('h9', mac='00:00:00:00:00:09', ip= '10.0.0.9')
        
        # Switches
        self.s1 = self.net.addSwitch('s1', cls=OVSKernelSwitch)
        self.s2 = self.net.addSwitch('s2', cls=OVSKernelSwitch)
        self.s3 = self.net.addSwitch('s3', cls=OVSKernelSwitch)

        self.s4 = self.net.addSwitch('s4', cls=OVSKernelSwitch)
        self.s5 = self.net.addSwitch('s5', cls=OVSKernelSwitch)

        info("*** Adding links\n")
        # S1 links
        self.net.addLink(self.h1, self.s1, bw=10, delay='0.0025ms')
        self.net.addLink(self.h2, self.s1, bw=10, delay='0.0025ms')        
        self.net.addLink(self.h3, self.s1, bw=10, delay='0.0025ms')

        # S2 links
        self.net.addLink(self.h4, self.s2, bw=10, delay='0.0025ms')
        self.net.addLink(self.h5, self.s2, bw=10, delay='0.0025ms')
        self.net.addLink(self.h6, self.s2, bw=10, delay='0.0025ms')

        # S3 links
        self.net.addLink(self.h7, self.s3, bw=10, delay='0.0025ms')
        self.net.addLink(self.h8, self.s3, bw=10, delay='0.0025ms')
        self.net.addLink(self.h9, self.s3, bw=10, delay='0.0025ms')

        # Switch-to-switch
        self.s1_to_s4 = self.net.addLink(self.s1, self.s4, bw=6, delay='25ms')
        self.s2_to_s4 = self.net.addLink(self.s2, self.s4, bw=6, delay='25ms')        
        self.s2_to_s5 = self.net.addLink(self.s2, self.s5, bw=6, delay='25ms')
        self.s3_to_s5 = self.net.addLink(self.s3, self.s5, bw=6, delay='25ms')
            
        info("*** Starting network\n")
        self.net.build()
        self.net.start()

...
if __name__ == '__main__':

    setLogLevel('info')
    info('starting the environment\n')
    env = Environment()

    info("*** Running CLI\n")
    CLI(env.net)
