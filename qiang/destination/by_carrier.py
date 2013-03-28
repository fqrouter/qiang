#!/usr/bin/env python
import socket
import re
import struct
import random
import sys

# Generate random ip from ip range of specific network carrier
# It is useful because for same carrier, GFW tend to install device in a very narrow ip range
# There are at least 6 major network carriers in China which have GFW attached to its boarder gateway
# The filtering and jamming behavior differ from carrier to carrier,
# which makes this carrier based ip selection interesting

RE_INETNUM = re.compile(r'inetnum:\s+(.+?)\s+-\s+(.+)', re.IGNORECASE)
RE_AUTNUM = re.compile(r'aut\-num:\s+AS(\d+)', re.IGNORECASE)

def main(carrier, query_type='ip', whoise_server='whois.apnic.net'):
    lines = query_whoise(whoise_server, '-i mb MAINT-%s' % carrier).splitlines()
    for line in lines:
        if 'asn' == query_type:
            query_asn(line)
        else:
            assert 'ip' == query_type
            query_ip(line)
    print('') # end indicator


def query_asn(line):
    result = RE_AUTNUM.findall(line)
    if result:
        print(result[0])


def query_ip(line):
    result = RE_INETNUM.findall(line)
    if result:
        start_ip, end_ip = result[0]
        if start_ip == end_ip:
            return start_ip
        else:
            try:
                print(get_random_ip_in_range(start_ip, end_ip))
            except:
                import traceback

                traceback.print_exc()
                print(start_ip, end_ip, '!!!')


def query_whoise(server, query):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(15)
    try:
        s.connect((server, 43))
        s.send((query + '\r\n').encode())
        response = b''
        while True:
            d = s.recv(4096)
            response += d
            if not d:
                break
    finally:
        s.close()
    return response


def get_random_ip_in_range(start_ip, end_ip):
# http://dregsoft.com/blog/?p=24
    start_ip_bytes = struct.unpack('!i', socket.inet_aton(start_ip))[0]
    end_ip_bytes = struct.unpack('!i', socket.inet_aton(end_ip))[0]
    random_ip_bytes = random.randrange(start_ip_bytes, end_ip_bytes)
    random_ip = socket.inet_ntoa(struct.pack('!i', random_ip_bytes))
    return random_ip


if 1 == len(sys.argv):
    print('[Usage] ./by_carrier.py carrier [ip|asn] [whoise_server] > ip_list.txt')
    print('China Telecom:\t\t\t\tCHINANET')
    print('China Unicom:\t\t\t\tCNCGROUP')
    print('China Mobile:\t\t\t\tCN-CMCC')
    print('China Railway Telecom:\t\t\tCN-CRTC')
    print('China Education & Research Network:\tCERNET-AP')
    print('China Science & Technology Network:\tCN-CSTNET')
    print('Can also: ./by_carrier.py CHINANET asn | ./by_asn @stdin')
    sys.exit(3)
else:
    main(*sys.argv[1:])

