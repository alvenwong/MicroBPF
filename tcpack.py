#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# tcpack   Trace TCP kernel-ACKed packets/segments.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# This provides information such as packet details, socket state, and kernel
# stack trace for packets/segments that were dropped via tcp_ack().
#
# USAGE: tcpack [-c] [-h] [-l]
#
# This uses dynamic tracing of kernel functions, and will need to be updated
# to match kernel changes.
#
# Copyright 2018 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 30-May-2018   Brendan Gregg   Created this.
# 3-Sep-2018 Zhuang Wang    Modified from tcpdrop to tcpack

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
import ctypes as ct
from time import sleep
from bcc import tcp
import argparse
from os import kill, getpid
from signal import SIGKILL

# arguments
examples = """examples:
    ./tcpack             # trace all ACKs
    ./tcpack -p  5205    # only trace port 5205
    ./tcpack -dp 5205    # only trace remote port 5205
    ./tcpack -sp 5205    # only trace local port 5205
    ./tcpack -s 5        # only trace one ACK in every 2^5 ACKs
"""

parser = argparse.ArgumentParser(
    description="Trace the TCP metrics with ACKs",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--port", 
    help="TCP port")
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
#include <uapi/linux/tcp.h>
#include <uapi/linux/ip.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>
#include <bcc/proto.h>


struct ipv4_flow_info {
    u64 init_time;
    u16 mss;
    u32 fastRe;
    u32 timeout;
    u32 last_cwnd;
    u32 max_bytes_inflight;
};
BPF_HASH(flows_info, struct sock *, struct ipv4_flow_info);


// only consider data structs for ipv4
struct ipv4_data_t {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 state;
    u8 tcpflags;
    u32 snd_cwnd;
    u32 rcv_wnd;
    u32	total_retrans;
    u32 fastRe;
    u32 timeout;
    u64 bytes_acked;
    u64 bytes_received;
    u32 srtt;
    u64 srtt_sum;
    u32 srtt_counter;
    // flight size
    u32 packets_out;
    u64 duration;
    u32 bytes_inflight;
};
BPF_PERF_OUTPUT(ipv4_events);

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


int trace_tcp_ack(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb)
{
    if (sk == NULL)
        return 0;

    // pull in details from the packet headers and the sock struct
    u16 family = sk->__sk_common.skc_family;
    if (family != AF_INET)
        return 0;

    u32 pid = bpf_get_current_pid_tgid();
    u64 time = bpf_ktime_get_ns();
    SAMPLING
    char state = sk->__sk_common.skc_state;
    u32 ack_seq = 0, seq = 0, snd_cwnd = 0;
    u16 sport = 0, dport = 0;
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    u8 tcpflags = ((u_int8_t *)tcp)[13];
    sport = tcp->source;
    dport = tcp->dest;
    sport = ntohs(sport);
    dport = ntohs(dport);

    FILTER_DPORT
    FILTER_SPORT

    struct ipv4_flow_info *finfo, zero = {};
    finfo = flows_info.lookup_or_init(&sk, &zero);
    struct ipv4_data_t data4 = {};
    u32 srtt = 0;
    data4.pid = pid;
    data4.saddr = ip->saddr;
    data4.daddr = ip->daddr;
    data4.dport = dport;
    data4.sport = sport;
    data4.state = state;
    data4.tcpflags = tcpflags;
    data4.snd_cwnd = tp->snd_cwnd;
    data4.rcv_wnd = tp->rcv_wnd;
    data4.bytes_acked = tp->bytes_acked;
    data4.bytes_received = tp->bytes_received;
    data4.total_retrans = tp->total_retrans;
    data4.fastRe = finfo->fastRe;
    data4.timeout = finfo->timeout;
    data4.srtt = tp->srtt_us;
    data4.srtt_counter += 1;
    data4.srtt_sum += tp->srtt_us;
    data4.packets_out = tp->packets_out;
    data4.duration = bpf_ktime_get_ns() - finfo->init_time;
    data4.bytes_inflight = tp->snd_nxt - tp->snd_una; 
    // if (finfo->max_bytes_inflight < bytes_inflight) {
    //    finfo->max_bytes_inflight = bytes_inflight;

    ipv4_events.perf_submit(ctx, &data4, sizeof(data4));

    return 0;
}


int trace_tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state)
{
    if (state == TCP_ESTABLISHED) {
        u64 ts = bpf_ktime_get_ns();
        struct tcp_sock *tp = (struct tcp_sock *)sk;
        struct ipv4_flow_info *finfo, zero = {};
        finfo = flows_info.lookup_or_init(&sk, &zero);
        finfo->init_time = ts;
        finfo->mss == tp->advmss;
    } else if (state == TCP_CLOSE) {
        flows_info.delete(&sk);
    }

    return 0;
} 


int trace_tcp_enter_recovery(struct pt_regs *ctx, struct sock *sk)
{
    struct ipv4_flow_info *finfo, zero = {};
    finfo = flows_info.lookup_or_init(&sk, &zero);
    finfo->fastRe += 1;

    return 0;
}


int trace_tcp_enter_loss(struct pt_regs *ctx, struct sock *sk)
{
    struct ipv4_flow_info *finfo, zero = {};
    finfo = flows_info.lookup_or_init(&sk, &zero);
    finfo->timeout += 1;

    return 0;
}
"""

# code substitutions
if args.port:
    bpf_text = bpf_text.replace('FILTER_PORT',
        'if (sport != %s && dport != %s) { return 0; }' % (args.port, args.port))
else:
    bpf_text = bpf_text.replace('FILTER_SPORT', '')
if args.sport:
    bpf_text = bpf_text.replace('FILTER_SPORT',
        'if (sport != %s) { return 0; }' % args.sport)
else:
    bpf_text = bpf_text.replace('FILTER_SPORT', '')
    
if args.dport:
    bpf_text = bpf_text.replace('FILTER_DPORT',
        'if (dport != %s) { return 0; }' % args.dport)
else:
    bpf_text = bpf_text.replace('FILTER_DPORT', '')
if args.sample:
    bpf_text = bpf_text.replace('SAMPLING',
        'if ((time << (64-%s) >> (64-%s)) != ((0x01 << %s) - 1)) { return 0;}' % (args.sample, args.sample, args.sample))
else:
    bpf_text = bpf_text.replace('SAMPLING', '')

# event data
class Data_ipv4(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("saddr", ct.c_uint),
        ("daddr", ct.c_uint),
        ("sport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("state", ct.c_ubyte),
        ("tcpflags", ct.c_ubyte),
        ("snd_cwnd", ct.c_uint),
        ("rcv_wnd", ct.c_uint),
        ("total_retrans", ct.c_uint),
        ("fastRe", ct.c_uint),
        ("timeout", ct.c_uint),
        ("bytes_acked", ct.c_ulonglong),
        ("bytes_received", ct.c_ulonglong),
        ("srtt", ct.c_uint),
        ("srtt_sum", ct.c_ulonglong),
        ("srtt_counter", ct.c_uint),
        ("packets_out", ct.c_uint),
        ("duration", ct.c_ulonglong),
        ("bytes_inflight", ct.c_uint),
    ]

# process event
def print_ipv4_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_ipv4)).contents
    print("%-8s %-4d %-20s > %-20s %-8s %-8s %-8s %-8s (%s)" % (
        strftime("%H:%M:%S"), event.pid,
        "%s:%d" % (inet_ntop(AF_INET, pack('I', event.saddr)), event.sport),
        "%s:%d" % (inet_ntop(AF_INET, pack('I', event.daddr)), event.dport),
        "%d" % (event.srtt / 1000),
        "%d" % (event.bytes_acked >> 10),
        "%d" % (event.bytes_received >> 10),
        tcp.tcpstate[event.state], tcp.flags2str(event.tcpflags)))

# initialize BPF
b = BPF(text=bpf_text)
trace_prefix = "trace_"
functions_list = ["tcp_ack", "tcp_set_state", "tcp_enter_recovery", "tcp_enter_loss"]
for i in range(len(functions_list)):
    function = functions_list[i]
    trace_function = trace_prefix + function
    if b.get_kprobe_functions(function):
        b.attach_kprobe(event=function, fn_name=trace_function)
    else:
        print("ERROR: %s() kernel function not found or traceable." % (function))
        exit()

# header
print("%-8s %-4s %-20s > %-20s %-8s %-8s %-8s %-8s (%s)" % ("TIME", "PID",
    "SADDR:SPORT", "DADDR:DPORT", "RTT(ms)", "ACKED(KB)", "RECVD(KB)", "STATE", "FLAGS"))

# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        kill(getpid(), SIGKILL)
