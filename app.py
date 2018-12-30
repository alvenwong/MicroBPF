#!/usr/bin/env python

from __future__ import print_function
from bcc import BPF
from time import strftime
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
import ctypes as ct
from bcc import tcp
from os import kill, getpid, path
from subprocess import call
from signal import SIGKILL
import argparse
import sys
from tcptools import check_filename, valid_function_name
from clock import Time

# arguments
examples = """examples:
    ./app                  # trace all TCP packets
    ./app -p  5205    # only trace port 5205
    ./app -s  5       # only trace one packet in every 2^5 packets
    ./app -o  [fname] # print the information into /usr/local/bcc/fname
"""

parser = argparse.ArgumentParser(
    description="Measure the latency in the application layer",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--port", nargs='?', const="80",
    help="TCP port")
parser.add_argument("-s", "--sample",
    help="Trace sampling")
parser.add_argument("-o", "--output", nargs='?', const="app",
    help="Output file")

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
#include <net/tcp.h>
#include <net/ip.h>

struct pair_tuple {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 seq;
    u32 ack;
};


struct ktime_info {
    u64 rcv_time;
    u64 send_time;
};


struct data_t {
    u64 app_time;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 seq;
    u32 ack;
};

BPF_HASH(pairs, struct pair_tuple, struct ktime_info);
BPF_PERF_OUTPUT(pair_events);

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


// request tuples: (SIP, SPORT, DIP, DPORT, SEQ A, ACK B)
// response tuples: (DIP, DPORT, SIP, SPORT, SEQ B, ACK A+len)

int trace_skb_copy_datagram_iter(struct pt_regs *ctx, struct sk_buff *skb)
{
    if (skb == NULL)
        return 0;

    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct pair_tuple ptuple = {};
    u16 sport = 0, dport = 0;
    u32 seq = 0, ack = 0; 

    ptuple.saddr = ip->saddr;
    ptuple.daddr = ip->daddr;
    sport = tcp->source;
    dport = tcp->dest;
    ptuple.sport = ntohs(sport);
    ptuple.dport = ntohs(dport);
    seq = tcp->seq;
    ack = tcp->ack_seq;
    ptuple.seq = ntohl(seq) + skb->len;
    ptuple.ack = ntohl(ack);

    SAMPLING
    FILTER_PORT
    
    struct ktime_info *tinfo, zero={};
    if ((tinfo = pairs.lookup_or_init(&ptuple, &zero)) == NULL)
        return 0;
    tinfo->rcv_time = bpf_ktime_get_ns();

    return 0;
}


int trace_tcp_transmit_skb(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb, int clone_it, gfp_t gfp_mask, u32 rcv_nxt)
{
    if (skb == NULL)
        return 0;

    u16 family = sk->__sk_common.skc_family;
    if (family == AF_INET) {
        struct pair_tuple ptuple = {};
        struct tcp_skb_cb *tcb;
        u16 dport = 0;
        ptuple.daddr = sk->__sk_common.skc_rcv_saddr;
        ptuple.saddr = sk->__sk_common.skc_daddr;
        ptuple.dport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ptuple.sport = ntohs(dport);
        tcb = TCP_SKB_CB(skb);
        ptuple.ack = tcb->seq; 
        ptuple.seq = rcv_nxt;

        SAMPLING
        FILTER_PORT

        struct ktime_info *tinfo;
        if ((tinfo = pairs.lookup(&ptuple)) == NULL)
            return 0;

        tinfo->send_time = bpf_ktime_get_ns();
        struct data_t data = {};
        data.app_time = tinfo->send_time - tinfo->rcv_time;
        data.daddr = ptuple.saddr;
        data.saddr = ptuple.daddr;
        data.dport = ptuple.sport;
        data.sport = ptuple.dport;
        data.seq = ptuple.seq;
        data.ack = ptuple.ack;
  
        pairs.delete(&ptuple);
        pair_events.perf_submit(ctx, &data, sizeof(data));
    }
    
    return 0;
}

"""

# code substitutions
if args.port:
    bpf_text = bpf_text.replace('FILTER_PORT',
        'if (ptuple.sport != %s && ptuple.dport != %s) { return 0; }' % (args.port, args.port))
else:
    bpf_text = bpf_text.replace('FILTER_PORT', '')
    
if args.sample:
    bpf_text = bpf_text.replace('SAMPLING',
        'if (((ptuple.seq + ptuple.ack) << (32-%s) >> (32-%s)) != ((0x01 << %s) - 1)) { return 0;}' % (args.sample, args.sample, args.sample))
else:
    bpf_text = bpf_text.replace('SAMPLING', '')


if args.output:
    if check_filename(args.output):
        output_dir = "/usr/local/bcc/"
        if not path.isdir(output_dir):
            call(["mkdir", "-p", output_dir])
        output_file = output_dir + args.output
        sys.stdout = open(output_file, "w+", buffering=1)
    else:
        print("The output filename is invalid. Exit...")
        exit()
 

class Data_t(ct.Structure):
    _fields_ = [
        ("app_time", ct.c_ulonglong),
        ("saddr", ct.c_uint),
        ("daddr", ct.c_uint),
        ("sport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("seq", ct.c_uint),
        ("ack", ct.c_uint),
    ]


# process event
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_t)).contents
    print("5 %-20s -> %-20s %-12s %-12s %-10s" % (
        "%s:%d" % (inet_ntop(AF_INET, pack('I', event.saddr)), event.sport),
        "%s:%d" % (inet_ntop(AF_INET, pack('I', event.daddr)), event.dport),
        "%d" % (event.seq),
        "%d" % (event.ack),
        "%d" % (event.app_time/1000)))


# initialize BPF
b = BPF(text=bpf_text)
trace_prefix = "trace_"
kprobe_functions_list = ["tcp_transmit_skb", "skb_copy_datagram_iter"]
for i in range(len(kprobe_functions_list)):
    function = kprobe_functions_list[i]
    trace_function = trace_prefix + function
    function = valid_function_name(function)
    if function == None:
        exit()
    if b.get_kprobe_functions(function):
        b.attach_kprobe(event=function, fn_name=trace_function)
    else:
        print("ERROR: %s() kernel function not found or traceable." % (function))
        exit()

# header
if not args.output:
    print("5 %-20s -> %-20s %-12s %-12s %-10s" % ("SADDR:SPORT", "DADDR:DPORT", "SEQ", "ACK", "APP"))

# read events
b["pair_events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        kill(getpid(), SIGKILL)
