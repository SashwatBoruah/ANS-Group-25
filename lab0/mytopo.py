from mininet.topo import Topo

class MyTopo(Topo):
    def build(self):
        # 1. Add Switches [cite: 237, 243]
        # We name them s1 and s2 as shown in Figure 1
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        # 2. Add Hosts [cite: 235, 243]
        # We assign IPs 10.0.0.1 to 10.0.0.4 [cite: 245]
        h1 = self.addHost('h1', ip='10.0.0.1')
        h2 = self.addHost('h2', ip='10.0.0.2')
        h3 = self.addHost('h3', ip='10.0.0.3')
        h4 = self.addHost('h4', ip='10.0.0.4')

        # 3. Add Links with specific properties [cite: 239, 247]
        # e1 to e4: 15 Mbps bandwidth, 10 ms delay
        opts_low = dict(bw=15, delay='10ms')
        self.addLink(h1, s1, **opts_low) # e1
        self.addLink(h2, s1, **opts_low) # e2
        self.addLink(h3, s2, **opts_low) # e3
        self.addLink(h4, s2, **opts_low) # e4

        # e5: 20 Mbps bandwidth, 45 ms delay (The link between switches)
        opts_high = dict(bw=20, delay='45ms')
        self.addLink(s1, s2, **opts_high) # e5

# This part tells Mininet how to identify your custom class [cite: 253]
topos = { 'mytopo': ( lambda: MyTopo() ) }