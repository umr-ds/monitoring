#!/usr/bin/python

# Simple network monitor - 1s interval csv stats dumper
# Copyright (c) 2016 Lars Baumgaertner
#
# requires dpkt and pcap python packages
#
# usage: sudo ./netmon.py <networkinterface>

import dpkt, pcap
import signal
import sys
import time

def signal_handler(signum, frame):
        print('You pressed Ctrl+C!')
        print_total_stats()
        sys.exit(0)

def log_handler(signum, frame):
    print_cur_stats()
    signal.alarm(1)

def print_header():
    print "timestamp_ms,cnt_pkt,cnt_ip,cnt_tcp,cnt_udp,size_pkt,size_ip,size_tcp,size_udp"

def print_total_stats_human():
    print "\n" , "="*40
    print "Packet counts total:"
    print "#Pkts: ", total_cnt['pkt']
    print "#IP: ", total_cnt['ip']
    print "#tcp: ", total_cnt['tcp']
    print "#udp: ", total_cnt['udp']
    print "\nPacket size counts total:"
    print "Pkts: ", total_size['pkt']
    print "IP: ", total_size['ip']
    print "tcp: ", total_size['tcp']
    print "udp: ", total_size['udp']

def print_total_stats():
    csv_line = "TOTAL,"
    csv_line += "%d,%d,%d,%d" % (total_cnt['pkt'],total_cnt['ip'],total_cnt['tcp'],total_cnt['udp'])
    csv_line += ",%d,%d,%d,%d" % (total_size['pkt'],total_size['ip'],total_size['tcp'],total_size['udp'])
    print csv_line

def print_cur_stats():
    cur_time = int(time.time() * 1000)
    csv_line = str(cur_time) + ','
    csv_line += "%d,%d,%d,%d" % (cur_cnt['pkt'],cur_cnt['ip'],cur_cnt['tcp'],cur_cnt['udp'])
    csv_line += ",%d,%d,%d,%d" % (cur_size['pkt'],cur_size['ip'],cur_size['tcp'],cur_size['udp'])
    print csv_line

    for i in cur_cnt.keys():
        cur_cnt[i] = 0
    for i in cur_size.keys():
        cur_size[i] = 0

    last_time = cur_time



if len(sys.argv) != 2:
    print "usage: %s <interface>" % sys.argv[0]
    sys.exit(1)

pc = pcap.pcap(name=sys.argv[1])

total_cnt = {'pkt':0, 'ip':0, 'tcp':0, 'udp':0}
total_size = {'pkt':0, 'ip':0, 'tcp':0, 'udp':0}

cur_cnt = {'pkt':0, 'ip':0, 'tcp':0, 'udp':0}
cur_size = {'pkt':0, 'ip':0, 'tcp':0, 'udp':0}


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGALRM, log_handler)

print_header()
last_time = time.time()
signal.alarm(1)
try:
    for timestamp, raw_buf in pc:
        output = {}

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(raw_buf)

        packet_size = len(raw_buf)

        cur_cnt['pkt'] += 1
        total_cnt['pkt'] += 1

        cur_size['pkt'] += packet_size
        total_size['pkt'] += packet_size

        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue

        ip = eth.data

        cur_cnt['ip'] += 1
        total_cnt['ip'] += 1

        cur_size['ip'] += packet_size
        total_size['ip'] += packet_size

        if ip.p==dpkt.ip.IP_PROTO_TCP:
           TCP=ip.data
           cur_cnt['tcp'] += 1
           total_cnt['tcp'] += 1
           cur_size['tcp'] += packet_size
           total_size['tcp'] += packet_size
        elif ip.p==dpkt.ip.IP_PROTO_UDP:
           UDP=ip.data
           cur_cnt['udp'] += 1
           total_cnt['udp'] += 1
           cur_size['udp'] += packet_size
           total_size['udp'] += packet_size

except KeyboardInterrupt:
    #print('You pressed Ctrl+C!')
    print_total_stats()
    sys.exit(0)
