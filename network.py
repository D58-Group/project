from mininet.topo import Topo

class SnifferTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        sn = self.addHost('sn')

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(sn, s1)

topos = {'sniffer': SnifferTopo}

#run with: 
#sudo mn --custom network.py --topo sniffer --mac --switch ovsbr --controller none


#to run our sniffer: 
#sn /home/mininet/project/packet_sniffer -i h1-eth0

#to run in background: 
#sn /home/mininet/project/packet_sniffer -i h1-eth0 &

#to flush
#h1 ps aux | grep packet_sniffer