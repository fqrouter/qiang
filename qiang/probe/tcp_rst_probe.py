#!/usr/bin/env python
import sys
import time
import os
import socket
import struct
import atexit
from scapy.layers.inet import IP, TCP, IPerror, TCPerror
from scapy.layers.dns import DNS, DNSQR

SYS_PATH = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if SYS_PATH not in sys.path:
    sys.path.append(SYS_PATH)
from qiang import networking

# Probe using the fact GFW will send back TCP RST if keyword detected in HTTP GET URL or HOST
#
# Send SYN with TTL 1
# PROBE =SYN=> ROUTER-1 (TTL is 1)
# PROBE <=ICMP_TTL_EXCEEDED= ROUTER-1
# Router will send back a ICMP packet tell us its (the router) ip address
#
# Send offending payload after SYN (A.K.A GET facebook.com) with TTL 1
# PROBE =OFFENDING_PAYLOAD=> ROUTER-1 (TTL is 1)
# PROBE <=ICMP_TTL_EXCEEDED= ROUTER-1
# Router will send back a ICMP packet tell us its (the router) ip address
#
# Send SYN with big enough TTL
# PROBE =OFFENDING_PAYLOAD => ROUTER-1 .. => ROUTER ATTACHED GFW (TTL is N)
# PROBE <=ICMP_TTL_EXCEEDED= ROUTER-1 .. <= ROUTER ATTACHED GFW
# SYN just by itself does not trigger GFW
#
# Send offending payload after SYN (A.K.A GET facebook.com) with big enough TTL
# PROBE =OFFENDING_PAYLOAD => ROUTER-1 .. => ROUTER ATTACHED GFW (TTL is N)
# PROBE <=ICMP_TTL_EXCEEDED= ROUTER-1 .. <= ROUTER ATTACHED GFW
# PROBE <=RST= ROUTER-1 .. <=ROUTER ATTACHED GFW (RST was sent by GFW to jam the connection)
# SYN by itself does not trigger GFW. Offending payload by itself does not trigger GFW as well.
# Only if SYN follows the ACK in a short time, and keyword in the HTTP GET URL or HOST will trigger.
# SYN+ACK will not be sent back in this case, as SYN never reaches the destination.
# The RST sent back from GFW will have TTL different from other packets sent back from destination.
# So by checking TTL of returning packets we can tell if GFW is jamming the connection.
# Also based on the ICMP packet we can tell the ip address of router attached GFW.

ERROR_CONNECTION_RESET = 104
ERROR_NO_DATA = 11
TH_SYN = 0x02        # synchronize sequence numbers
TH_RST = 0x04        # reset connection
TH_ACK = 0x10        # acknowledgment number set
SPORT = 19840
HTTP_DPORT = 80
DNS_DPORT = 53
SMTP_DPORT = 25
ROOT_USER_ID = 0


def main(dst, ttl, probe_type_code='HTTP', waits_for_syn_ack=False):
    probe_types = list_probe_types()
    probe_type = probe_types[probe_type_code]
    iface, src, _ = networking.get_route(dst)
    dport = probe_type.get_default_dport()
    if ROOT_USER_ID == os.geteuid():
        sniffer = networking.create_sniffer(iface, src, dst)
        probe = probe_type(
            src, SPORT, dst, dport, int(ttl), sniffer,
            waits_for_syn_ack=waits_for_syn_ack)
        sniffer.start_sniffing()
        probe.poke()
        time.sleep(2)
        sniffer.stop_sniffing()
        report = probe.peek()
    else:
        probe = probe_type(src, SPORT, dst, dport, int(ttl), sniffer=None)
        probe.poke()
        time.sleep(2)
        report = probe.peek()
    packets = report.pop('PACKETS')
    print(report)
    for mark, packet in packets:
        formatted_packet = packet.sprintf('%.time% %IP.src% -> %IP.dst% %TCP.flags%')
        print('[%s] %s' % (mark, formatted_packet))


def list_probe_types():
    return {
        'HTTP': HttpTcpRstProbe,
        'DNS': DnsTcpRstProbe,
        'SMTP_HELO_RCPT_TO': SmtpHeloRcptToTcpRstProbe,
        'SMTP_MAIL_FROM': SmtpMailFromTcpRstProbe,
        'SMTP_RCPT_TO': SmtpRcptToTcpRstProbe
    }


class TcpRstProbe(object):
    def __init__(self, src, sport, dst, dport, ttl, sniffer,
                 interval_between_syn_and_offending_payload=0.5,
                 waits_for_syn_ack=False):
        self.src = src
        self.sport = sport
        self.dst = dst
        self.dport = dport
        self.ttl = ttl
        self.sniffer = sniffer
        self.interval_between_syn_and_offending_payload = interval_between_syn_and_offending_payload
        self.waits_for_syn_ack = waits_for_syn_ack
        self.report = self.initialize_report({
            'ROUTER_IP_FOUND_BY_SYN': None,
            'ROUTER_IP_FOUND_BY_OFFENDING_PAYLOAD': None,
            'SYN_ACK?': None,
            'RST_AFTER_SYN?': None,
            'RST_AFTER_OFFENDING_PAYLOAD?': None,
            'PACKETS': []
        })
        self.tcp_socket = None
        self.offending_payload_sent_at = None

    @classmethod
    def initialize_report(cls, report):
        return report

    def poke(self):
        self.send_syn()
        time.sleep(self.interval_between_syn_and_offending_payload)
        self.offending_payload_sent_at = time.time()
        self.send_offending_payload()

    def send_syn(self):
        if self.sniffer:
            packet = IP(src=self.src, dst=self.dst, id=self.ttl * 10 + 1,
                        ttl=64 if self.waits_for_syn_ack else self.ttl) / \
                     TCP(sport=self.sport, dport=self.dport, flags='S', seq=0)
            networking.send(packet)
            self.report['PACKETS'].append(('SYN', packet))
            if self.waits_for_syn_ack:
                self.wait_for_syn_ack()
        else:
            self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            atexit.register(networking.immediately_close_tcp_socket_so_sport_can_be_reused, self.tcp_socket)
            self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp_socket.settimeout(2)
            self.tcp_socket.bind((self.src, self.sport)) # if sport change the route going through might change
            self.tcp_socket.connect((self.dst, self.dport))

    def wait_for_syn_ack(self):
        for i in range(10):
            time.sleep(0.3)
            self.peek()
            if self.report['SYN_ACK?']:
                return
        raise Exception('SYN ACK not received')

    def close(self):
        networking.immediately_close_tcp_socket_so_sport_can_be_reused(self.tcp_socket)

    def send_offending_payload(self):
        if self.sniffer:

            packet = IP(src=self.src, dst=self.dst, id=self.ttl * 10 + 2, ttl=self.ttl) / \
                     TCP(sport=self.sport, dport=self.dport, flags='A',
                         seq=1, ack=self.report['SYN_ACK?'] or 100) / self.get_offending_payload()
            networking.send(packet)
            self.report['PACKETS'].append(('OFFENDING_PAYLOAD', packet))
        else:
            self.tcp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)
            try:
                self.tcp_socket.send(self.get_offending_payload())
            except socket.error as e:
                if ERROR_CONNECTION_RESET == e[0]:
                    self.report['RST_AFTER_SYN?'] = True
                else:
                    raise

    def get_offending_payload(self):
        raise NotImplementedError()

    def peek(self):
        if self.sniffer:
            for packet in self.sniffer.packets:
                if TCP in packet:
                    self.analyze_tcp_packet(packet)
                elif IPerror in packet and TCPerror in packet:
                    self.analyze_tcp_error_packet(packet)
            return self.report
        else:
            if not self.report['RST_AFTER_SYN?']:
                self.tcp_socket.settimeout(0)
                try:
                    self.tcp_socket.recv(1024)
                    self.tcp_socket.recv(1024)
                except socket.error as e:
                    if ERROR_CONNECTION_RESET == e[0]:
                        self.report['RST_AFTER_OFFENDING_PAYLOAD?'] = True
                    elif ERROR_NO_DATA == e[0]:
                        pass
                    else:
                        raise
            return self.report

    def analyze_tcp_packet(self, packet):
        if self.dport != packet[TCP].sport:
            return
        if self.sport != packet[TCP].dport:
            return
        if packet[TCP].flags & TH_SYN and packet[TCP].flags & TH_ACK:
            self.record_syn_ack(packet)
        elif packet[TCP].flags & TH_RST:
            if not self.offending_payload_sent_at or packet.time < self.offending_payload_sent_at:
                self.record_rst_after_syn(packet)
            else:
                self.record_rst_after_offending_payload(packet)
        else:
            self.report['PACKETS'].append((self.handle_unknown_packet(packet), packet))

    def analyze_tcp_error_packet(self, packet):
        if self.sport != packet[TCPerror].sport:
            return
        if self.dport != packet[TCPerror].dport:
            return
        if self.ttl * 10 + 1 == packet[IPerror].id:
            self.record_router_ip_found_by_syn(packet.src, packet)
        elif self.ttl * 10 + 2 == packet[IPerror].id:
            self.record_router_ip_found_by_offending_payload(packet.src, packet)
        else:
            self.report['PACKETS'].append((self.handle_unknown_packet(packet), packet))

    def handle_unknown_packet(self, packet):
        return 'UNKNOWN'

    def record_syn_ack(self, packet):
        if self.report['SYN_ACK?']:
            self.report['PACKETS'].append(('ADDITIONAL_SYN_ACK', packet))
        else:
            self.report['PACKETS'].append(('SYN_ACK', packet))
            self.report['SYN_ACK?'] = packet[TCP].seq

    def record_rst_after_syn(self, packet):
        if self.report['RST_AFTER_SYN?']:
            self.report['PACKETS'].append(('ADDITIONAL_RST_AFTER_SYN', packet))
        else:
            self.report['PACKETS'].append(('RST_AFTER_SYN', packet))
            self.report['RST_AFTER_SYN?'] = True

    def record_rst_after_offending_payload(self, packet):
        if self.report['RST_AFTER_OFFENDING_PAYLOAD?']:
            self.report['PACKETS'].append(('ADDITIONAL_RST_AFTER_OFFENDING_PAYLOAD', packet))
        else:
            self.report['PACKETS'].append(('RST_AFTER_OFFENDING_PAYLOAD', packet))
            self.report['RST_AFTER_OFFENDING_PAYLOAD?'] = True

    def record_router_ip_found_by_syn(self, router_ip, packet):
        if self.report['ROUTER_IP_FOUND_BY_SYN']:
            self.report['PACKETS'].append(('ADDITIONAL_ROUTER_IP_FOUND_BY_SYN', packet))
        else:
            self.report['PACKETS'].append(('ROUTER_IP_FOUND_BY_SYN', packet))
            self.report['ROUTER_IP_FOUND_BY_SYN'] = router_ip

    def record_router_ip_found_by_offending_payload(self, router_ip, packet):
        if self.report['ROUTER_IP_FOUND_BY_OFFENDING_PAYLOAD']:
            self.report['PACKETS'].append(('ADDITIONAL_ROUTER_IP_FOUND_BY_OFFENDING_PAYLOAD', packet))
        else:
            self.report['PACKETS'].append(('ROUTER_IP_FOUND_BY_OFFENDING_PAYLOAD', packet))
            self.report['ROUTER_IP_FOUND_BY_OFFENDING_PAYLOAD'] = router_ip


class ThreePacketTcpRstProbe(TcpRstProbe):
# SYN, OFFENDING_PAYLOAD_1, OFFENDING_PAYLOAD_2
    @classmethod
    def get_default_dport(cls):
        return SMTP_DPORT

    def send_offending_payload(self):
        if self.sniffer:
            packet = IP(src=self.src, dst=self.dst, id=self.ttl * 10 + 2, ttl=self.ttl) / \
                     TCP(sport=self.sport, dport=self.dport, flags='A', seq=1, ack=100)
            networking.send(packet)
            self.report['PACKETS'].append(('OFFENDING_PAYLOAD_1', packet))
            packet = IP(src=self.src, dst=self.dst, id=self.ttl * 10 + 3, ttl=self.ttl) / \
                     TCP(sport=self.sport, dport=self.dport, flags='A', seq=1, ack=100) / self.get_offending_payload()
            networking.send(packet)
            self.report['PACKETS'].append(('OFFENDING_PAYLOAD_2', packet))
        else:
            self.tcp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)
            try:
                self.tcp_socket.send(self.get_offending_payload())
            except socket.error as e:
                if ERROR_CONNECTION_RESET == e[0]:
                    self.report['RST_AFTER_SYN?'] = True
                else:
                    raise

    def handle_unknown_packet(self, packet):
        if IPerror in packet and self.ttl * 10 + 3 == packet[IPerror].id:
            if self.report.get('ROUTER_IP_FOUND_BY_OFFENDING_PAYLOAD_2'):
                return 'ADDITIONAL_ROUTER_IP_FOUND_BY_OFFENDING_PAYLOAD_2'
            else:
                self.report['ROUTER_IP_FOUND_BY_OFFENDING_PAYLOAD_2'] = packet.src
                return 'ROUTER_IP_FOUND_BY_OFFENDING_PAYLOAD_2'
        return super(ThreePacketTcpRstProbe, self).handle_unknown_packet(packet)


class DnsTcpRstProbe(TcpRstProbe):
    @classmethod
    def get_default_dport(cls):
        return DNS_DPORT

    def get_offending_payload(self):
        offending_payload = str(DNS(rd=1, qd=DNSQR(qname="dl.dropbox.com")))
        return struct.pack("!H", len(offending_payload)) + offending_payload


class HttpTcpRstProbe(TcpRstProbe):
    @classmethod
    def get_default_dport(cls):
        return HTTP_DPORT

    def get_offending_payload(self):
        return 'GET / HTTP/1.1\r\nHost: www.facebook.com\r\n\r\n'


class SmtpMailFromTcpRstProbe(ThreePacketTcpRstProbe):
    def get_offending_payload(self):
        return 'MAIL FROM: xiazai@upup.info\r\n'


class SmtpRcptToTcpRstProbe(ThreePacketTcpRstProbe):
    def get_offending_payload(self):
        return 'RCPT TO: xiazai@upup.info\r\n'


class SmtpHeloRcptToTcpRstProbe(TcpRstProbe):
    @classmethod
    def get_default_dport(cls):
        return SMTP_DPORT

    @classmethod
    def initialize_report(cls, report):
        return dict(report, USER_NOT_LOCAL_ERROR=None)

    def get_offending_payload(self):
        return 'HELO 163.com\r\nRCPT TO: xiazai@upup.info\r\n'

    def handle_unknown_packet(self, packet):
        if TCP in packet and '551 User not local; please try <forward-path>\r\n' == packet[TCP].payload:
            self.report['USER_NOT_LOCAL_ERROR'] = True
            return 'USER_NOT_LOCAL_ERROR'
        return super(SmtpHeloRcptToTcpRstProbe, self).handle_unknown_packet(packet)


if '__main__' == __name__:
    import argparse

    argument_parser = argparse.ArgumentParser(description="Detect GFW attached router using the TCP RST sent back")
    argument_parser.add_argument('destination', help='ip address to shoot at')
    argument_parser.add_argument('ttl', type=int)
    argument_parser.add_argument('--probe', choices=list_probe_types().keys(), default='HTTP')
    argument_parser.add_argument('--behind-firewall', action='store_const', const=True)
    args = argument_parser.parse_args()
    main(args.destination, args.ttl, probe_type_code=args.probe, waits_for_syn_ack=args.behind_firewall)
