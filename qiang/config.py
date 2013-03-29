sniffer_type = 'L2' # can be L3 or Tcpdump, but L2 is working more reliably
min_ttl = 3
max_ttl = 20
debug = True
batch_size = 4
output_dir = 'var'
interval_between_poke_and_peek = 2

fixed_route = None
# uncomment below if you have a broken routing table
# which caused the detected outgoing ip or interface is wrong
#fixed_route = ('venet0:0', 'a.b.c.d')

# tcp_route_probe must not be None
# it is used to test if route changes when sport/dport changed
tcp_route_probe = {
    'a_sport': 9264,
    'b_sport': 8375,
    'c_sport': 7486,
    'a_dport': 6597,
    'b_dport': 5618,
    'c_dport': 4729
}

# udp_route_probe must not be None
# it is used to test if route changes when sport/dport changed
udp_route_probe = {
    'a_sport': 9264,
    'b_sport': 8375,
    'c_sport': 7486,
    'a_dport': 6597,
    'b_dport': 5618,
    'c_dport': 4729
}

dns_wrong_answer_probe = {
    'sport': 19841,
    'dport': 53
}
# uncomment below to disable dns_wrong_answer_probe
# dns_wrong_answer_probe = None

http_tcp_rst_probe = {
    'sport': 19842,
    'dport': 80,
    'interval_between_syn_and_http_get': 0.5
}
# uncomment below to disable http_tcp_rst_probe
# http_tcp_rst_probe = None

dns_tcp_rst_probe = {
    'sport': 19843,
    'dport': 53,
    'interval_between_syn_and_dns_question': 0.5
}
# uncomment below to disable dns_tcp_rst_probe
# dns_tcp_rst_probe = None

smtp_mail_from_tcp_rst_probe = {
    'sport': 19844,
    'dport': 25,
    'interval_between_syn_and_mail_from': 0.5
}
# uncomment below to disable smtp_mail_from_tcp_rst_probe
# smtp_mail_from_tcp_rst_probe = None

smtp_rcpt_to_tcp_rst_probe = {
    'sport': 19845,
    'dport': 25,
    'interval_between_syn_and_rcpt_to': 0.5
}
# uncomment below to disable smtp_rcpt_to_tcp_rst_probe
# smtp_rcpt_to_tcp_rst_probe = None

smtp_helo_rcpt_to_tcp_rst_probe = {
    'sport': 19846,
    'dport': 25,
    'interval_between_syn_and_helo': 0.5
}
# uncomment below to disable smtp_helo_rcpt_to_tcp_rst_probe
# smtp_helo_rcpt_to_tcp_rst_probe = None

tcp_packet_drop_probe = None
# uncomment below if you have tcp port being blocked by GFW
# if dport is blocked, set the sport to the same
# if sport is blocked, set the dport to the same
# example below demonstrated the case which sport 8080 is blocked
#tcp_packet_drop_probe = {
#    'blocked_sport': 8080,
#    'comparison_sport': 8081,
#    'blocked_dport': 1234,
#    'comparison_dport': 1234
#}

udp_packet_drop_probe = None
# uncomment below if you have udp port being blocked by GFW
# if dport is blocked, set the sport to the same
# if sport is blocked, set the dport to the same
# example below demonstrated the case which sport 8080 is blocked
#udp_packet_drop_probe = {
#    'blocked_sport': 8080,
#    'comparison_sport': 8081,
#    'blocked_dport': 53,
#    'comparison_dport': 53
#}

# config below works whne you probe from abroad to China
# if you want to probe from China to abroad, change the settings below
# to provide abroad ip
ip_providers = [
    'by_carrier.py CHINANET | limit.py 50',
    'by_carrier.py CNCGROUP | limit.py 50',
    'by_carrier.py CN-CMCC | limit.py 50',
    'by_carrier.py CN-CRTC | limit.py 50',
    'by_carrier.py CERNET-AP | limit.py 50',
    'by_carrier.py CN-CSTNET | limit.py 50'
]

# you can use a file at ~/.qiang.cfg to override settings in this config file
import os
import sys

QIANG_CFG_PATH = os.path.join(os.getenv('HOME'), '.qiang.cfg')
if os.path.exists(QIANG_CFG_PATH):
    with open(QIANG_CFG_PATH) as f:
        user_config_code = compile(f.read(), QIANG_CFG_PATH, 'exec')
    user_config = {}
    exec user_config_code in user_config
    sys.modules[__name__].__dict__.update(user_config)

if not os.path.exists(output_dir):
    os.mkdir(output_dir)