__import__('scapy.route')
from scapy.config import conf
import os


def make_route_fixed(outbound_iface, outbound_ip):
    conf.route.ifadd(outbound_iface, '%s/0' % outbound_ip)


def get_route(dst):
    return conf.route.route(dst)

OUTBOUND_IFACE = os.getenv('OUTBOUND_IFACE')
OUTBOUND_IP = os.getenv('OUTBOUND_IP')
if OUTBOUND_IFACE and OUTBOUND_IP:
    make_route_fixed(OUTBOUND_IFACE, OUTBOUND_IP)