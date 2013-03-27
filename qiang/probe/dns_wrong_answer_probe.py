#!/usr/bin/env python
import sys
import os
import time
import socket
import atexit
from scapy.layers.inet import IP, UDP, UDPerror, IPerror
from scapy.layers.dns import DNS, DNSQR

SYS_PATH = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if SYS_PATH not in sys.path:
    sys.path.append(SYS_PATH)
from qiang import networking

# Probe using the fact GFW will send back wrong dns answer if the dns question is about certain domain name
#
# Send offending payload (A.K.A try resolve domain name twitter.com) with TTL 1
# PROBE =OFFENDING_PAYLOAD=> ROUTER-1 (TTL is 1)
# PROBE <=ICMP_TTL_EXCEEDED= ROUTER-1
# Router will send back a ICMP packet tell us its (the router) ip address
#
# Send offending payload (A.K.A try resolve domain name twitter.com) with big enough TTL
# PROBE =OFFENDING_PAYLOAD => ROUTER-1 .. => ROUTER ATTACHED GFW (TTL is N)
# PROBE <=ICMP_TTL_EXCEEDED= ROUTER-1 .. <= ROUTER ATTACHED GFW
# PROBE <=WRONG_DNS_ANSWER= ROUTER-1 .. <=ROUTER ATTACHED GFW (WRONG_DNS_ANSWER was sent by GFW)
# The wrong dns answer sent back by GFW will be accepted by our browser so will try to access twitter.com
# via a wrong ip address. To tell if the answer is right or wrong, check the list below.
# When we found a wrong answer, we know the router is attached with GFW. The ip adress of the router
# can be told from the ICMP packet sent back previously.

# source http://zh.wikipedia.org/wiki/%E5%9F%9F%E5%90%8D%E6%9C%8D%E5%8A%A1%E5%99%A8%E7%BC%93%E5%AD%98%E6%B1%A1%E6%9F%93
WRONG_ANSWERS = set([
    '4.36.66.178',
    '8.7.198.45',
    '37.61.54.158',
    '46.82.174.68',
    '59.24.3.173',
    '64.33.88.161',
    '64.33.99.47',
    '64.66.163.251',
    '65.104.202.252',
    '65.160.219.113',
    '66.45.252.237',
    '72.14.205.99',
    '72.14.205.104',
    '78.16.49.15',
    '93.46.8.89',
    '128.121.126.139',
    '159.106.121.75',
    '169.132.13.103',
    '192.67.198.6',
    '202.106.1.2',
    '202.181.7.85',
    '203.161.230.171',
    '207.12.88.98',
    '208.56.31.43',
    '209.36.73.33',
    '209.145.54.50',
    '209.220.30.174',
    '211.94.66.147',
    '213.169.251.35',
    '216.221.188.182',
    '216.234.179.13'
])

DNS_TYPE_A = 1
SPORT = 19840
DPORT = 53
ROOT_USER_ID = 0

def main(dst, ttl):
    iface, src, _ = networking.get_route(dst)
    if ROOT_USER_ID == os.geteuid():
        sniffer = networking.create_sniffer(iface, src, dst)
        probe = DnsWrongAnswerProbe(src, SPORT, dst, DPORT, int(ttl), sniffer)
        sniffer.start_sniffing()
        probe.poke()
        time.sleep(2)
        sniffer.stop_sniffing()
        report = probe.peek()
    else:
        probe = DnsWrongAnswerProbe(src, SPORT, dst, DPORT, int(ttl), sniffer=None)
        probe.poke()
        time.sleep(2)
        report = probe.peek()
        report.pop('ROUTER_IP')
    report.pop('PACKETS')
    print(report)


class DnsWrongAnswerProbe(object):
    def __init__(self, src, sport, dst, dport, ttl, sniffer):
        self.src = src
        self.sport = sport
        self.dst = dst
        self.dport = dport
        self.ttl = ttl
        self.sniffer = sniffer
        self.report = {
            'ROUTER_IP': None,
            'WRONG_ANSWER': None,
            'RIGHT_ANSWER': None,
            'PACKETS': []
        }
        self.udp_socket = None

    def poke(self):
        question = DNS(rd=1, qd=DNSQR(qname='twitter.com'))
        if self.sniffer:
            packet = IP(dst=self.dst, src=self.src, id=self.ttl, ttl=self.ttl) / UDP(
                sport=self.sport) / question
            networking.send(packet)
            self.report['PACKETS'].append(('QUESTION', packet))
        else:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            atexit.register(self.udp_socket.close)
            self.udp_socket.settimeout(0)
            self.udp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)
            self.udp_socket.bind((self.src, self.sport))
            self.udp_socket.sendto(str(question), (self.dst, self.dport))

    def peek(self):
        if self.sniffer:
            packets = self.sniffer.packets
        else:
            packets = networking.dump_socket(self.udp_socket, packet_class=DNS)
            self.udp_socket.close()
        for packet in packets:
            if DNS in packet:
                self.analyze_dns_packet(packet)
            elif IPerror in packet and UDPerror in packet:
                self.analyze_udp_error_packet(packet)
        return self.report

    def close(self):
        if self.udp_socket:
            self.udp_socket.close()

    def analyze_dns_packet(self, packet):
        if UDP in packet:
            if self.dport != packet[UDP].sport:
                return
            if self.sport != packet[UDP].dport:
                return
        if 0 == packet[DNS].ancount:
            return self.record_wrong_answer('[BLANK]', packet)
        for i in range(packet[DNS].ancount):
            if DNS_TYPE_A == packet[DNS].an[i].type:
                answer = packet[DNS].an[i].rdata
                if answer in WRONG_ANSWERS:
                    return self.record_wrong_answer(answer, packet)
                else:
                    return self.record_right_answer(answer, packet)
        self.report['PACKETS'].append('UNKNOWN', packet)

    def analyze_udp_error_packet(self, packet):
        if self.sport != packet[UDPerror].sport:
            return
        if self.dport != packet[UDPerror].dport:
            return
        self.record_router_ip(packet.src, packet)

    def record_wrong_answer(self, wrong_answer, packet):
        if self.report['WRONG_ANSWER']:
            self.report['PACKETS'].append(('ADDITIONAL_WRONG_ANSWER', packet))
        else:
            self.report['PACKETS'].append(('WRONG_ANSWER', packet))
            self.report['WRONG_ANSWER'] = wrong_answer

    def record_right_answer(self, right_answer, packet):
        if self.report['RIGHT_ANSWER']:
            self.report['PACKETS'].append(('ADDITIONAL_RIGHT_ANSWER', packet))
        else:
            self.report['PACKETS'].append(('RIGHT_ANSWER', packet))
            self.report['RIGHT_ANSWER'] = right_answer

    def record_router_ip(self, router_ip, packet):
        if self.report['ROUTER_IP']:
            self.report['PACKETS'].append(('ADDITIONAL_ROUTER_IP', packet))
        else:
            self.report['PACKETS'].append(('ROUTER_IP', packet))
            self.report['ROUTER_IP'] = router_ip

if '__main__' == __name__:
    if 1 == len(sys.argv):
        print('[Usage] ./dns_wrong_answer_probe.py destination_ip ttl')
        sys.exit(3)
    else:
        main(*sys.argv[1:])