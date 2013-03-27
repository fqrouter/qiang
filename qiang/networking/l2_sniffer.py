#!/usr/bin/env python
import select
import threading
import contextlib
import traceback
import sys
from scapy.layers.inet import IP, IPerror
from scapy.config import conf

class L2Sniffer(threading.Thread):
    def __init__(self, iface, src, dst, no_filter=True):
        super(L2Sniffer, self).__init__()
        self.daemon = True
        self.no_filter = no_filter
        self.iface = iface
        self.src = src
        self.dst = dst
        self.started = threading.Event()
        self.started.clear()
        self.should_stop = False
        self.packets = []

    def run(self):
        try:
            if self.no_filter:
                filter = None # for PPP link
            else:
                filter = '(dst host %s and src host %s) or icmp' % (self.src, self.dst)
            with contextlib.closing(conf.L2listen(iface=self.iface, filter=filter)) as l2_listen_socket:
                self.started.set()
                while True:
                    result = select.select([l2_listen_socket], [], [], 0.1)
                    if l2_listen_socket not in result[0]:
                        if self.should_stop:
                            return # no data and should stop => stop
                        continue
                    packet = l2_listen_socket.recv(2048)
                    if IP in packet:
                        packet = packet[IP]
                    else:
                        continue
                    self.collect_packet(packet)
        except:
            traceback.print_exc()

    def start_sniffing(self):
        self.start()
        self.started.wait(1)

    def stop_sniffing(self):
        self.should_stop = True
        self.join()
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
        print('[Usage] ./l2_sniffer.py destination_ip')
        sys.exit(3)
    else:
        import routing_table

        dst = sys.argv[1]
        no_filter = True
        iface, src, _ = routing_table.get_route(dst)
        sniffer = L2Sniffer(iface, src, dst, no_filter=no_filter)
        sniffer.start_sniffing()
        print('press enter to stop...')
        sys.stdin.readline()
        for packet in sniffer.stop_sniffing():
            print(packet.time, packet.src, packet.dst)