#!/usr/bin/env python
import socket
import os
import sys
import time
import atexit
from scapy.layers.inet import IP, UDP, IPerror, UDPerror
from scapy.layers.dns import DNS, DNSQR

SYS_PATH = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if SYS_PATH not in sys.path:
    sys.path.append(SYS_PATH)
from qiang import networking

# Probe using the fact GFW will configure some router to only drop packet of certain source ip and port combination
#
# Normally GFW does not drop your packet, it will jam the connection using TCP RST or FAKE DNS ANSWER.
# However, if you are running some OpenVPN like service on the server and being detected *somehow* by GFW,
# it will block your ip or just a specific port of that ip. We can use the fact some router is dropping packet
# to show its connection with GFW.
#
# Send offending payload (A.K.A source port being the blocked port) with TTL 1
# PROBE =OFFENDING_PAYLOAD=> ROUTER-1 (TTL is 1)
# PROBE <=ICMP_TTL_EXCEEDED= ROUTER-1
# Router will send back a ICMP packet tell us its (the router) ip address
#
# Send offending payload (A.K.A source port being the blocked port) with big enough TTL
# PROBE =OFFENDING_PAYLOAD => ROUTER-1 .. => ROUTER ATTACHED GFW (TTL is N)
# PROBE <=NOTHING= (Nothing returned after 2 seconds)
# We know the router is dropping our packet as no ICMP being returned
#
# Send non-offending payload (A.K.A source port being the reference port) with big enough TTL
# PROBE =NON_OFFENDING_PAYLOAD => ROUTER-1 .. => ROUTER ATTACHED GFW (TTL is N)
# PROBE <=ICMP_TTL_EXCEEDED= ROUTER-1 .. <= ROUTER ATTACHED GFW
# Although the router ip returned from this ICMP might not be same router, as source port was not the same.
# But there is a great chance the router is the same router, as we can tell same router is responsible for
# TCP RST and FAKE DNS ANSWER.

ERROR_NO_DATA = 11
TH_SYN = 0x02        # synchronize sequence numbers
TH_ACK = 0x10        # acknowledgment number set
ROOT_USER_ID = 0

def main(dst, sport, ttl):
    iface, src, _ = networking.get_route(dst)
    if ROOT_USER_ID == os.geteuid():
        sniffer = networking.create_sniffer(iface, src, dst)
        probe = UdpPacketDropProbe(src, int(sport), dst, 53, int(ttl), sniffer)
        sniffer.start_sniffing()
        probe.poke()
        time.sleep(2)
        sniffer.stop_sniffing()
        report = probe.peek()
    else:
        probe = UdpPacketDropProbe(src, int(sport), dst, 53, int(ttl), sniffer=None)
        probe.poke()
        time.sleep(2)
        report = probe.peek()
    packets = report.pop('PACKETS')
    print(report)
    for mark, packet in packets:
        formatted_packet = packet.sprintf('%.time% %IP.src% -> %IP.dst% %TCP.flags%')
        print('[%s] %s' % (mark, formatted_packet))


class UdpPacketDropProbe(object):
    def __init__(self, src, sport, dst, dport, ttl, sniffer, one_packet_only=False):
        self.src = src
        self.sport = sport
        self.dst = dst
        self.dport = dport
        self.ttl = ttl
        self.sniffer = sniffer
        self.one_packet_only = one_packet_only
        self.report = {
            'ROUTER_IP_FOUND_BY_PACKET_1': None,
            'ROUTER_IP_FOUND_BY_PACKET_2': None,
            'ROUTER_IP_FOUND_BY_PACKET_3': None,
            'RESPONDED?': None,
            'PACKETS': []
        }
        self.udp_socket = None

    def poke(self):
        question = DNS(rd=1, qd=DNSQR(qname='www.gov.cn'))
        if self.sniffer:
            packet1 = IP(src=self.src, dst=self.dst, id=self.ttl * 10 + 1, ttl=self.ttl) / UDP(
                sport=self.sport, dport=self.dport) / question
            networking.send(packet1)
            self.report['PACKETS'].append(('PACKET_1', packet1))
            if not self.one_packet_only:
                packet2 = IP(src=self.src, dst=self.dst, id=self.ttl * 10 + 2, ttl=self.ttl) / UDP(
                    sport=self.sport, dport=self.dport) / question
                networking.send(packet2)
                self.report['PACKETS'].append(('PACKET_2', packet2))
                packet3 = IP(src=self.src, dst=self.dst, id=self.ttl * 10 + 3, ttl=self.ttl) / UDP(
                    sport=self.sport, dport=self.dport) / question
                networking.send(packet3)
                self.report['PACKETS'].append(('PACKET_3', packet3))
        else:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            atexit.register(self.udp_socket.close)
            self.udp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)
            self.udp_socket.settimeout(0)
            self.udp_socket.bind((self.src, self.sport)) # if sport change the route going through might change
            self.udp_socket.sendto(str(question), (self.dst, self.dport))

    def close(self):
        if self.udp_socket:
            self.udp_socket.close()

    def peek(self):
        if not self.sniffer:
            try:
                self.udp_socket.recv(1024)
                self.report['RESPONDED?'] = True
            except socket.error as e:
                if ERROR_NO_DATA == e[0]:
                    pass
                else:
                    raise
            return self.report
        for packet in self.sniffer.packets:
            if UDP in packet:
                self.analyze_udp_packet(packet)
            elif IPerror in packet and UDPerror in packet:
                self.analyze_udp_error_packet(packet)
        return self.report

    def analyze_udp_packet(self, packet):
        if self.dport != packet[UDP].sport:
            return
        if self.sport != packet[UDP].dport:
            return
        self.report['RESPONDED?'] = True
        self.report['PACKETS'].append(('UNKNOWN', packet))

    def analyze_udp_error_packet(self, packet):
        if self.sport != packet[UDPerror].sport:
            return
        if self.dport != packet[UDPerror].dport:
            return
        self.report['RESPONDED?'] = True
        if self.ttl * 10 + 1 == packet[IPerror].id:
            self.record_router_ip(packet.src, 1, packet)
        elif self.ttl * 10 + 2 == packet[IPerror].id:
            self.record_router_ip(packet.src, 2, packet)
        elif self.ttl * 10 + 3 == packet[IPerror].id:
            self.record_router_ip(packet.src, 3, packet)
        else:
            self.report['PACKETS'].append(('UNKNOWN', packet))

    def record_router_ip(self, router_ip, packet_index, packet):
        if self.report['ROUTER_IP_FOUND_BY_PACKET_%s' % packet_index]:
            self.report['PACKETS'].append(('ADDITIONAL_ROUTER_IP_FOUND_BY_PACKET_%s' % packet_index, packet))
        else:
            self.report['PACKETS'].append(('ROUTER_IP_FOUND_BY_PACKET_%s' % packet_index, packet))
            self.report['ROUTER_IP_FOUND_BY_PACKET_%s' % packet_index] = router_ip

if '__main__' == __name__:
    if 1 == len(sys.argv):
        print('[Usage] ./udp_packet_drop_probe.py destination_ip sport ttl')
        sys.exit(3)
    else:
        main(*sys.argv[1:])