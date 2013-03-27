# abstraction layer of sending/receiving ip packet

from .routing_table import get_route
from .routing_table import make_route_fixed
from .raw_socket_sender import send
from .l3_sniffer import dump_socket

def create_sniffer(iface, src, dst, sniffer_type='L3', **kwargs):
    from .l3_sniffer import L3Sniffer
    from .l2_sniffer import L2Sniffer
    from .tcpdump_sniffer import TcpdumpSniffer

    if 'L3' == sniffer_type:
        return L3Sniffer(src, dst)
    elif 'L2' == sniffer_type:
        return L2Sniffer(iface, src, dst, **kwargs)
    else:
        assert 'TCPDUMP' == sniffer_type
        return TcpdumpSniffer(iface, src, dst)


def immediately_close_tcp_socket_so_sport_can_be_reused(tcp_socket):
    import socket
    import struct

    if not tcp_socket:
        return
    l_onoff = 1
    l_linger = 0
    tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', l_onoff, l_linger))
    tcp_socket.close()

__all__ = [
    get_route.__name__,
    make_route_fixed.__name__,
    send.__name__,
    create_sniffer.__name__,
    dump_socket.__name__,
    immediately_close_tcp_socket_so_sport_can_be_reused.__name__
]
