#!/usr/bin/env python
import subprocess
import tempfile
import sys
from scapy.layers.inet import IP, IPerror
from scapy.utils import rdpcap

class TcpdumpSniffer(object):
    def __init__(self, iface, src, dst):
        self.iface = iface
        self.src = src
        self.dst = dst
        self.packets = []

    def start_sniffing(self):
        self.pcap_file_path = tempfile.mktemp()
        filter = '(dst host %s and src host %s) or icmp' % (self.src, self.dst)
        self.tcmpdump_proc = subprocess.Popen(
            ['tcpdump', '-i', self.iface, '-w', self.pcap_file_path, filter],
            stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=subprocess.PIPE)

    def stop_sniffing(self):
        self.tcmpdump_proc.terminate()
        self.tcmpdump_proc.wait()
        for packet in rdpcap(self.pcap_file_path):
            if IP in packet:
                self.collect_packet(packet[IP])
        return self.packets

    def collect_packet(self, packet):
        packet.mark = None
        if self.dst == packet.src and self.src == packet.dst:
            self.packets.append(packet)
        elif IPerror in packet:
            if self.src == packet[IPerror].src and self.dst == packet[IPerror].dst:
                self.packets.append(packet)


if '__main__' == __name__:
    if 1 == len(sys.argv):
        print('[Usage] ./tcpdump_sniffer.py destination_ip')
        sys.exit(3)
    else:
        import routing_table

        dst = sys.argv[1]
        iface, src, _ = routing_table.get_route(dst)
        sniffer = TcpdumpSniffer(iface, src, dst)
        sniffer.start_sniffing()
        print('capturing at %s between %s and %s, press enter to stop...' % (iface, src, dst))
        sys.stdin.readline()
        for packet in sniffer.stop_sniffing():
            print(packet.time, packet.src, packet.dst)