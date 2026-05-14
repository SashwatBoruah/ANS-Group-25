"""
 Copyright (c) 2026 Computer Networks Group @ UPB
 
 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """
 
#!/bin/env python3
 
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
 
 
class NetworkTopo(Topo):
 
    def __init__(self):
 
        Topo.__init__(self)
 
        # Link parameters as required by the lab spec (15 Mbps, 10 ms)
        link_opts = dict(bw=15, delay='10ms')
 
        # Hosts with IP addresses and default gateways
        h1  = self.addHost('h1',  ip='10.0.1.2/24',      defaultRoute='via 10.0.1.1')
        h2  = self.addHost('h2',  ip='10.0.1.3/24',      defaultRoute='via 10.0.1.1')
        ser = self.addHost('ser', ip='10.0.2.2/24',      defaultRoute='via 10.0.2.1')
        ext = self.addHost('ext', ip='192.168.1.123/24', defaultRoute='via 192.168.1.1')
 
        # Switches (s1, s2) and Router (s3) - all OVSKernelSwitch
        # The controller decides whether each behaves as a switch or router
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        s2 = self.addSwitch('s2', protocols='OpenFlow13')
        s3 = self.addSwitch('s3', protocols='OpenFlow13')  # acts as router
 
        # Internal hosts connect to switch s1
        self.addLink(h1, s1, **link_opts)
        self.addLink(h2, s1, **link_opts)
 
        # Internal server connects to switch s2
        self.addLink(ser, s2, **link_opts)
 
        # Router s3 connects the two switches and the external host
        # Port order matters for the controller port_to_ip / port_to_mac maps:
        #   s3 port 1 -> s1   (gateway 10.0.1.1,    MAC 00:00:00:00:01:01)
        #   s3 port 2 -> s2   (gateway 10.0.2.1,    MAC 00:00:00:00:01:02)
        #   s3 port 3 -> ext  (gateway 192.168.1.1,  MAC 00:00:00:00:01:03)
        self.addLink(s3, s1,  **link_opts)
        self.addLink(s3, s2,  **link_opts)
        self.addLink(s3, ext, **link_opts)
 
 
def run():
    topo = NetworkTopo()
    net = Mininet(topo=topo,
                  switch=OVSKernelSwitch,
                  link=TCLink,
                  controller=None)
    net.addController(
        'c1',
        controller=RemoteController,
        ip="127.0.0.1",
        port=6653)
    net.start()
 
    # Ensure all switches use OpenFlow 1.3
    for sw in ['s1', 's2', 's3']:
        net[sw].cmd('ovs-vsctl set bridge {} protocols=OpenFlow13'.format(sw))
 
    CLI(net)
    net.stop()
 
 
if __name__ == '__main__':
    setLogLevel('info')
    run()