#!/usr/bin/env python
import re
import urllib2
import math
import struct
import socket
import random
import sys

RE_IP_RANGE = re.compile(r'([0-9]+(?:\.[0-9]+){3})/([0-9]+)')

def main(as_number=None):
    if '@stdin' == as_number:
        while True:
            as_number = sys.stdin.readline().strip()
            if as_number:
                list_ip_for_asn(as_number)
            else:
                return
    else:
        list_ip_for_asn(as_number)


def list_ip_for_asn(as_number):
    urllib2.socket.setdefaulttimeout(10)
    request = urllib2.Request('http://bgp.he.net/AS%s' % as_number)
    request.add_header('User-Agent',
        'Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.8.1.14) Gecko/20080404 (FoxPlus) Firefox/2.0.0.14')
    response = urllib2.urlopen(request)
    for ip_range in RE_IP_RANGE.findall(response.read()):
        start_ip, netmask = ip_range
        netmask = int(netmask)
        if netmask == 0:
            continue
        print(get_random_ip_in_range(start_ip, netmask))


def get_random_ip_in_range(start_ip, netmask):
# http://dregsoft.com/blog/?p=24
    ip_count = int(math.pow(2, 32 - netmask))
    start_ip_bytes = struct.unpack('!i', socket.inet_aton(start_ip))[0]
    random_ip_bytes = random.randrange(start_ip_bytes, start_ip_bytes + ip_count)
    random_ip = socket.inet_ntoa(struct.pack('!i', random_ip_bytes))
    return random_ip

if 1 == len(sys.argv):
    print('[Usage] ./by_asn.py as_number > ip_list.txt')
    print('@stdin is a special as_number indicating as number should be read from stdin')
    sys.exit(3)
else:
    main(*sys.argv[1:])