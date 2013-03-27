#!/usr/bin/env python
import socket
import threading
import contextlib
import traceback
import time
import sys
from scapy.arch.linux import get_last_packet_timestamp
from scapy.layers.inet import IP, IPerror

ERROR_NO_DATA = 11

class L3Sniffer(threading.Thread):
    def __init__(self, src, dst):
        super(L3Sniffer, self).__init__()
        self.daemon = True
        self.src = src
        self.dst = dst
        self.started = threading.Event()
        self.started.clear()
        self.should_stop = False
        self.packets = []

    def run(self):
        try:
            with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)) as icmp_socket:
                icmp_socket.settimeout(0)
                with contextlib.closing(
                    socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)) as udp_socket:
                    udp_socket.settimeout(0)
                    with contextlib.closing(
                        socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)) as tcp_socket:
                        tcp_socket.settimeout(0)
                        self.started.set()
                        self.capture(icmp_socket, udp_socket, tcp_socket)

        except:
            traceback.print_exc()

    def capture(self, icmp_socket, udp_socket, tcp_socket):
        while True:
            icmp_packet = try_receive_packet(icmp_socket)
            udp_packet = try_receive_packet(udp_socket)
            tcp_packet = try_receive_packet(tcp_socket)
            if icmp_packet is not None:
                self.collect_packet(icmp_packet)
            if udp_packet is not None:
                self.collect_packet(udp_packet)
            if tcp_packet is not None:
                self.collect_packet(tcp_packet)
            if icmp_packet is None and udp_packet is None and tcp_packet is None:
                if self.should_stop:
                    return
                else:
                    time.sleep(0.1)

    def collect_packet(self, packet):
        packet.mark = None
        if self.dst == packet.src and self.src == packet.dst:
            self.packets.append(packet)
        elif IPerror in packet:
            if self.src == packet[IPerror].src and self.dst == packet[IPerror].dst:
                self.packets.append(packet)

    def start_sniffing(self):
        self.start()
        self.started.wait(1)

    def stop_sniffing(self):
        self.should_stop = True
        self.join()
        return self.packets


def dump_socket(s, packet_class):
    packets = []
    while True:
        packet = try_receive_packet(s, packet_class)
        if packet is None:
            return packets
        else:
            packets.append(packet)


def try_receive_packet(s, packet_class=IP):
    try:
        packet = packet_class(s.recv(1024))
        packet.time = get_last_packet_timestamp(s)
        return packet
    except socket.error as e:
        if ERROR_NO_DATA == e[0]:
            return None
        else:
            raise


if '__main__' == __name__:
    if 1 == len(sys.argv):
        print('[Usage] ./l3_sniffer.py destination_ip')
        sys.exit(3)
    else:
        import routing_table

        dst = sys.argv[1]
        _, src, _ = routing_table.get_route(dst)
        sniffer = L3Sniffer(src, dst)
        sniffer.start_sniffing()
        print('press enter to stop...')
        sys.stdin.readline()
        for packet in sniffer.stop_sniffing():
            print(packet.time, packet.src, packet.dst)