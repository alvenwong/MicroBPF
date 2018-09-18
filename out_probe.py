#!/usr/bin/env python

from __future__ import print_function
from bcc import BPF
from time import strftime
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
import ctypes as ct
from bcc import tcp
import os
import signal
import argparse

# arguments
examples = """examples:
    ./out_probe             # trace all TCP packets
    ./out_porbe -dp 5205    # only trace remote port 5205
    ./out_porbe -sp 5205    # only trace local port 5205
    ./out_porbe -s  100     # only trace one packet in every 100 packets
"""

parser = argparse.ArgumentParser(
    description="Trace the duration in TCP, IP and mac layers",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-sp", "--sport", 
    help="TCP source port")
parser.add_argument("-dp", "--dport",
    help="TCP destination port")
parser.add_argument("-s", "--sample",
    help="Trace sampling")

args = parser.parse_args()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#define KBUILD_MODNAME "foo"
#include <linux/tcp.h>
#include <linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/ip.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <net/tcp.h>
#include <net/ip.h>


struct packet_tuple {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 seq;
};


struct ktime_info {
    u64 mac_time;
    u64 ip_time;
    u64 tcp_time;
    u64 app_time;
    u32 counter;
};

struct data_t {
    u64 mac_time;
    u64 ip_time;
    u64 tcp_time;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 seq;
};

BPF_HASH(out_timestamps, struct packet_tuple, struct ktime_info);
BPF_PERF_OUTPUT(timestamp_events);

static struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb)
{
    // unstable API. verify logic in tcp_hdr() -> skb_transport_header().
    return (struct tcphdr *)(skb->head + skb->transport_header);
}

static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb)
{
    // unstable API. verify logic in ip_hdr() -> skb_network_header().
    return (struct iphdr *)(skb->head + skb->network_header);
}


int trace_dev_queue_xmit(struct pt_regs *ctx, struct sk_buff *skb)
{
    if (skb == NULL)
        return 0;

    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);

    struct packet_tuple pkt_tuple = {};
    pkt_tuple.saddr = ip->saddr;
    pkt_tuple.daddr = ip->daddr;
    u16 sport = 0, dport = 0;
    u32 seq = 0, ack_seq = 0;
    sport = tcp->source;
    dport = tcp->dest;
    sport = ntohs(sport);
    dport = ntohs(dport);
    pkt_tuple.sport = sport;
    pkt_tuple.dport = dport;
    seq = tcp->seq;
    pkt_tuple.seq = ntohl(seq);

    FILTER_DPORT
    FILTER_SPORT
    
    struct ktime_info *tinfo;
    if ((tinfo = out_timestamps.lookup(&pkt_tuple)) == NULL)
        return 0;
    tinfo->mac_time = bpf_ktime_get_ns();
    struct data_t data = {};
    data.mac_time = tinfo->mac_time - tinfo->ip_time;
    data.ip_time = tinfo->ip_time - tinfo->tcp_time;
    data.saddr = pkt_tuple.saddr;
    data.daddr = pkt_tuple.daddr;
    data.sport = pkt_tuple.sport;
    data.dport = pkt_tuple.dport;
    data.seq = pkt_tuple.seq;
    
    out_timestamps.delete(&pkt_tuple);
    timestamp_events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}


int trace_ip_queue_xmit(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb)
{
    if (skb == NULL)
        return 0;

    u16 family = sk->__sk_common.skc_family;
    if (family == AF_INET) {
        struct packet_tuple pkt_tuple = {};
        u16 dport = 0;
        u32 seq = 0;
        pkt_tuple.saddr = sk->__sk_common.skc_rcv_saddr;
        pkt_tuple.daddr = sk->__sk_common.skc_daddr;
        pkt_tuple.sport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        pkt_tuple.dport = ntohs(dport);
        struct tcphdr *tcp = skb_to_tcphdr(skb);
        seq = tcp->seq;
        pkt_tuple.seq = ntohl(seq);

        FILTER_DPORT
        FILTER_SPORT

        struct ktime_info *tinfo;
        if ((tinfo = out_timestamps.lookup(&pkt_tuple)) == NULL)
            return 0;
        tinfo->ip_time = bpf_ktime_get_ns();
    }
    
    return 0;
}

int trace___tcp_transmit_skb(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb)
{
    if (skb == NULL)
        return 0;

    u16 family = sk->__sk_common.skc_family;
    if (family == AF_INET) {
        struct packet_tuple pkt_tuple = {};
        struct tcp_skb_cb *tcb;
        u16 dport = 0;
        pkt_tuple.saddr = sk->__sk_common.skc_rcv_saddr;
        pkt_tuple.daddr = sk->__sk_common.skc_daddr;
        pkt_tuple.sport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        pkt_tuple.dport = ntohs(dport);
        tcb = TCP_SKB_CB(skb);
        pkt_tuple.seq = tcb->seq; 

        FILTER_DPORT
        FILTER_SPORT

        struct ktime_info *tinfo, zero = {};
        if ((tinfo = out_timestamps.lookup_or_init(&pkt_tuple, &zero)) == NULL)
            return 0;
        tinfo->tcp_time = bpf_ktime_get_ns();
        tinfo->counter += 1;
    }
    
    return 0;
}

"""

# code substitutions
if args.sport:
    bpf_text = bpf_text.replace('FILTER_SPORT',
        'if (pkt_tuple.sport != %s) { return 0; }' % args.sport)
else:
    bpf_text = bpf_text.replace('FILTER_SPORT', '')
    
if args.dport:
    bpf_text = bpf_text.replace('FILTER_DPORT',
        'if (pkt_tuple.dport != %s) { return 0; }' % args.dport)
else:
    bpf_text = bpf_text.replace('FILTER_DPORT', '')
if args.sample:
    bpf_text = bpf_text.replace('SAMPLING',
        'if ((pkt_tuple.seq & 0x0000FFFD) >> 2 != %s) { return 0; }' % args.sample)
else:
    bpf_text = bpf_text.replace('SAMPLING', '')

class Data_t(ct.Structure):
    _fields_ = [
        ("mac_time", ct.c_ulonglong),
        ("ip_time", ct.c_ulonglong),
        ("tcp_time", ct.c_ulonglong),
        ("saddr", ct.c_uint),
        ("daddr", ct.c_uint),
        ("sport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("seq", ct.c_uint),
    ]

# process event
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_t)).contents
    print("%-20s > %-20s %-12s %-8s %-8s" % (
        "%s:%d" % (inet_ntop(AF_INET, pack('I', event.saddr)), event.sport),
        "%s:%d" % (inet_ntop(AF_INET, pack('I', event.daddr)), event.dport),
        "%d" % (event.seq),
        "%d" % (event.mac_time/1000),
        "%d" % (event.ip_time/1000)))


# initialize BPF
b = BPF(text=bpf_text)
trace_prefix = "trace_"
functions_list = ["__tcp_transmit_skb", "ip_queue_xmit", "dev_queue_xmit"]
for i in range(len(functions_list)):
    function = functions_list[i]
    trace_function = trace_prefix + function
    if b.get_kprobe_functions(function):
        b.attach_kprobe(event=function, fn_name=trace_function)
    else:
        print("ERROR: %s() kernel function not found or traceable." % (function))
        exit()

# read events
b["timestamp_events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        os.kill(os.getpid(), signal.SIGKILL)
