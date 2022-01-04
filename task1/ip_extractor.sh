#!/bin/bash
# adapted from https://gist.github.com/WJDigby/107f9330ad120ba4044c69e951cc953a

tcpdump -r provided/capture.pcap 'ip' -n                        | # get IP data from pcap
    grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' -o | # filter out everything except the addresses
    sort -u                                                       # remove duplicates
