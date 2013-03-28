#!/usr/bin/env python
import sys
import random

def main(limit):
    limit = int(limit)
    all_ips = []
    while True:
        ip = sys.stdin.readline().strip()
        if ip:
            all_ips.append(ip)
        else:
            break
    if len(all_ips) > limit:
        selected_ips = random.sample(all_ips, limit)
    else:
        selected_ips = all_ips
    for ip in selected_ips:
        print(ip)
    print('')

if 1 == len(sys.argv):
    print('[Usage] ./limit.py limit')
    print('it reads ip line by line from stdin, and pick limit from all')
    sys.exit(3)
else:
    main(*sys.argv[1:])