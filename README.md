# Mininet Project - SDN for Monitoring and Mitigation of DoS Attacks

The project consists of a Mininet topology composed of 4 hosts (h1, h2, h4 as clients, and h3 as a server) and 4 OVSKernelSwitches (Open vSwitch) connected to the hosts in the following way:
- h1 and h4 are connected to s1
- h2 is connected to s2
- s1 and s2 are connected to s3
- s3 is connected to s4
- h3 is connected to s4

The switches are controlled by an SDN Controller executed using the Ryu manager module and Python 3.9 (`python3.9 -m ryu.cmd.manager ...`).

Host h1 is the DoS attacker. The aim of the project is to create an SDN controller with monitoring and mitigation capabilities:

### The Topology
![image](https://github.com/user-attachments/assets/b03861eb-1c78-471f-bc3c-3e64fda7c4be)
