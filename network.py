from mininet.topo import Topo

#simple 1 switch-2 host topology 
class SnifferTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')

        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        self.addLink(h1, s1)
        self.addLink(h2, s1)


#multi hop topology 
class MultiHopTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        # Links
        self.addLink(h1, s1)
        self.addLink(s1, s2)
        self.addLink(s2, h2)


#star topology 
class StarTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')

        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')

        for host in [h1, h2, h3, h4]:
            self.addLink(host, s1)


#topology to show bottleneck 
class BottleneckTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        self.addLink(h1, s1)
        self.addLink(h2, s2)

       
        self.addLink(
            s1, s2,
            bw=1,                
            delay='20ms',
            max_queue_size=20,
            use_htb=True
        )


#middlebox topology
class MiddleboxTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        sn = self.addHost('sn')  

        self.addLink(h1, s1)
        self.addLink(s1, sn)
        self.addLink(sn, s2)
        self.addLink(s2, h2)


topos = {
    'sniffer': SnifferTopo,
    'multihop': MultiHopTopo,
    'star': StarTopo,
    'bottleneck': BottleneckTopo,
    'middlebox': MiddleboxTopo
}


#run with: 
#sudo mn --custom network.py --topo sniffer --mac --switch ovsk --controller none
# sudo mn --custom network.py --topo sniffer --mac --switch ovsbr --controller none
# sudo mnexec -a $(pgrep -f "mininet:h1") ./packet_sniffer -i eth0

#to run our sniffer: 
#sn /home/mininet/project/packet_sniffer -i h1-eth0

#to run in background: 
#sn /home/mininet/project/packet_sniffer -i h1-eth0 &

#to flush
#h1 ps aux | grep packet_sniffer