#!/usr/bin/env python3

import ipaddress

# read in allowed ip ranges
with open('provided/ip_ranges.txt', 'r') as f:
    ranges = f.readlines()

# read in ips from ip_extractor.sh
with open('ips.txt', 'r') as f:
    ips = f.readlines()

# convert to ip range and address types
ranges = [ipaddress.ip_network(r.strip()) for r in ranges]
ips = [ipaddress.ip_address(i.strip()) for i in ips]

# check if each ip is in any of the ranges
for i in ips:
    for r in ranges:
        if i in r:
            print(i)
