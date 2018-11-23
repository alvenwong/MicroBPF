#!/usr/bin/env python

from __future__ import print_function
from bcc import BPF
from time import strftime
from socket import inet_ntop, AF_INET, AF_INET6, gethostname, gethostbyname
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
    ./tcp             # trace all TCP packets
    ./tcp -p  5205    # only trace port 5205
    ./in_porbe -s  5       # only trace one packet in every 2^5 packets
    ./in_porbe -o  [fname] # print the information into /usr/local/bcc/fname
"""

parser = argparse.ArgumentParser(
    description="Trace the duration in TCP, IP and MAC layers",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--port", 
    help="TCP port")
parser.add_argument("-s", "--sample",
    help="Trace sampling")
parser.add_argument("-o", "--output", nargs='?', const="tcp",
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
#include <uapi/linux/if_ether.h>
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
    u32 ack;
};


struct ktime_info {
    u64 mac_in;
    u64 ip_in;
    u64 tcp_in;
    u64 app_in;
    u64 app_out;
    u64 tcp_out;
    u64 ip_out;
    u64 mac_out; 
};


struct data_ktime {
    u64 total;
    u64 mac_in;
    u64 mac_in_timestamp;
    u64 ip_in;
    u64 tcp_in;
    u64 app;
    u64 tcp_out;
    u64 ip_out;
    u64 mac_out;
    u64 mac_out_timestamp;
};


struct data_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 seq;
    u32 ack;
    struct data_ktime latencies;
};

BPF_HASH(timestamps, struct packet_tuple, struct ktime_info);
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

static inline int machdr_len(struct sk_buff *skb)
{
    return skb->mac_len;
}


static inline int iphdr_len(struct iphdr *ip)
{
    // BCC does not support bitfield
    // get iphdr->ihl if __BIG_ENDIAN_BITFIELD
    return ((*(u8 *)ip) & 0x0F) << 2;
}

static inline int tcphdr_len(struct tcphdr *tcp)
{
    // BCC does not support bitfield
    // get tcphdr->doff if __BIG_ENDIAN_BITFIELD
    return (*((u8 *)tcp + 12)) >> 4 << 2;
}


static void get_pkt_in_tuple(struct packet_tuple *pkt_tuple, struct iphdr *ip, struct tcphdr *tcp)
{
    u16 sport = 0, dport = 0;
    u32 seq = 0, ack = 0; 

    //pkt_tuple->saddr = ip->daddr;
    pkt_tuple->daddr = ip->saddr;
    sport = tcp->source;
    dport = tcp->dest;
    pkt_tuple->sport = ntohs(dport);
    pkt_tuple->dport = ntohs(sport);
    seq = tcp->seq;
    ack = tcp->ack_seq;
    pkt_tuple->ack = ntohl(seq);
    pkt_tuple->seq = ntohl(ack);
} 


static void get_pkt_out_tuple(struct packet_tuple *pkt_tuple, struct iphdr *ip, struct tcphdr *tcp)
{
    u16 sport = 0, dport = 0;
    u32 seq = 0, ack = 0; 

    pkt_tuple->daddr = ip->daddr;
    sport = tcp->source;
    dport = tcp->dest;
    pkt_tuple->sport = ntohs(sport);
    pkt_tuple->dport = ntohs(dport);
    seq = tcp->seq;
    ack = tcp->ack_seq;
    pkt_tuple->seq = ntohl(seq);
    pkt_tuple->ack = ntohl(ack);
} 

// request tuples: (SIP, SPORT, DIP, DPORT, SEQ A, ACK B)
// response tuples: (DIP, DPORT, SIP, SPORT, SEQ B, ACK A+len)

int trace_eth_type_trans(struct pt_regs *ctx, struct sk_buff *skb)
{
    const struct ethhdr* eth = (struct ethhdr*) skb->data;
    u16 protocol = eth->h_proto;
    // Protocol is IP
    if (protocol == 8) 
    {
        struct iphdr *ip = (struct iphdr *)(skb->data + 14);
        struct tcphdr *tcp = (struct tcphdr *)(skb->data + 34);
        struct packet_tuple pkt_tuple = {};
        get_pkt_in_tuple(&pkt_tuple, ip, tcp);

        u32 len = skb->len - machdr_len(skb) - iphdr_len(ip) - tcphdr_len(tcp);
        pkt_tuple.ack += len;
        
        SAMPLING
        FILTER_PORT

        struct ktime_info *tinfo, zero={}; 
        if ((tinfo = timestamps.lookup_or_init(&pkt_tuple, &zero)) == NULL)
            return 0;

        tinfo->mac_in = bpf_ktime_get_ns();
    }

    return 0;
}


int trace_ip_rcv(struct pt_regs *ctx, struct sk_buff *skb)
{
    if (skb == NULL)
        return 0;

    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {};
    get_pkt_in_tuple(&pkt_tuple, ip, tcp);

    u32 len = skb->len - iphdr_len(ip) - tcphdr_len(tcp);
    pkt_tuple.ack += len;

    SAMPLING
    FILTER_PORT

    struct ktime_info *tinfo;
    if ((tinfo = timestamps.lookup(&pkt_tuple)) == NULL)
        return 0;
    tinfo->ip_in = bpf_ktime_get_ns();
    
    return 0;
}

int trace_tcp_v4_rcv(struct pt_regs *ctx, struct sk_buff *skb)
{
    if (skb == NULL)
        return 0;

    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {};
    get_pkt_in_tuple(&pkt_tuple, ip, tcp);

    u32 len = skb->len - tcphdr_len(tcp);
    pkt_tuple.ack += len;

    SAMPLING
    FILTER_PORT

    struct ktime_info *tinfo;
    if ((tinfo = timestamps.lookup(&pkt_tuple)) == NULL)
        return 0;
    tinfo->tcp_in = bpf_ktime_get_ns();

    return 0;
}



int trace_skb_copy_datagram_iter(struct pt_regs *ctx, struct sk_buff *skb)
{
    if (skb == NULL)
        return 0;

    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {};
    get_pkt_in_tuple(&pkt_tuple, ip, tcp);

    pkt_tuple.ack += skb->len;

    SAMPLING
    FILTER_PORT
    
    struct ktime_info *tinfo;
    if ((tinfo = timestamps.lookup(&pkt_tuple)) == NULL)
        return 0;
    tinfo->app_in = bpf_ktime_get_ns();

    return 0;
}


int trace_tcp_transmit_skb(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb, int clone_it, gfp_t gfp_mask, u32 rcv_nxt)
{
    if (skb == NULL)
        return 0;

    u16 family = sk->__sk_common.skc_family;
    if (family == AF_INET) {
        struct packet_tuple pkt_tuple = {};
        struct tcp_skb_cb *tcb;
        u16 dport = 0;
        pkt_tuple.daddr = sk->__sk_common.skc_daddr;
        dport = sk->__sk_common.skc_dport;
        pkt_tuple.sport = sk->__sk_common.skc_num;
        pkt_tuple.dport = ntohs(dport);
        tcb = TCP_SKB_CB(skb);
        pkt_tuple.seq = tcb->seq; 
        pkt_tuple.ack = rcv_nxt;

        SAMPLING
        FILTER_PORT

        struct ktime_info *tinfo, zero = {};
        if ((tinfo = timestamps.lookup(&pkt_tuple)) == NULL)
            return 0;

        tinfo->app_out = bpf_ktime_get_ns();
    }
    
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
        u32 seq = 0, ack = 0;
        pkt_tuple.daddr = sk->__sk_common.skc_daddr;
        dport = sk->__sk_common.skc_dport;
        pkt_tuple.sport = sk->__sk_common.skc_num;
        pkt_tuple.dport = ntohs(dport);
        struct tcphdr *tcp = skb_to_tcphdr(skb);
        seq = tcp->seq;
        ack = tcp->ack_seq;
        pkt_tuple.seq = ntohl(seq);
        pkt_tuple.ack = ntohl(ack);

        SAMPLING
        FILTER_PORT

        struct ktime_info *tinfo;
        if ((tinfo = timestamps.lookup(&pkt_tuple)) == NULL)
            return 0;
        tinfo->tcp_out = bpf_ktime_get_ns();
    }
    
    return 0;
}


int trace_dev_queue_xmit(struct pt_regs *ctx, struct sk_buff *skb)
{
    if (skb == NULL)
        return 0;

    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {};
    get_pkt_out_tuple(&pkt_tuple, ip, tcp);

    SAMPLING
    FILTER_PORT

    struct ktime_info *tinfo;
    if ((tinfo = timestamps.lookup(&pkt_tuple)) == NULL)
        return 0;
    tinfo->ip_out = bpf_ktime_get_ns();

    return 0;
}


int trace_dev_hard_start_xmit(struct pt_regs *ctx, struct sk_buff *skb)
{
    if (skb == NULL)
        return 0;

    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {};
    get_pkt_out_tuple(&pkt_tuple, ip, tcp);

    SAMPLING
    FILTER_PORT

    struct ktime_info *tinfo;
    if ((tinfo = timestamps.lookup(&pkt_tuple)) == NULL)
        return 0;

    tinfo->mac_out = bpf_ktime_get_ns();

    struct data_t data = {};
    if (tinfo->app_in) {
        data.latencies.total  = tinfo->mac_out - tinfo->mac_in;
        data.latencies.mac_in = tinfo->ip_in - tinfo->mac_in;
        data.latencies.mac_in_timestamp = tinfo->mac_in;
        data.latencies.ip_in  = tinfo->tcp_in - tinfo->ip_in;
        data.latencies.tcp_in = tinfo->app_in - tinfo->tcp_in;
        data.latencies.app    = tinfo->app_out - tinfo->app_in;
    } else {
        timestamps.delete(&pkt_tuple);
        return 0;
    }

    data.latencies.tcp_out = tinfo->tcp_out - tinfo->app_out;
    data.latencies.ip_out  = tinfo->ip_out - tinfo->tcp_out;
    data.latencies.mac_out = tinfo->mac_out - tinfo->ip_out;
    data.latencies.mac_in_timestamp = tinfo->mac_out;

    data.sport = pkt_tuple.sport;
    data.daddr = pkt_tuple.daddr;
    //data.nat_saddr = ip->saddr;
    //data.nat_sport = ntohs(sport);
    data.dport = pkt_tuple.dport;
    data.seq = pkt_tuple.seq;
    data.ack = pkt_tuple.ack;
    
    timestamp_events.perf_submit(ctx, &data, sizeof(data));
    timestamps.delete(&pkt_tuple);

    return 0;
}

"""

# code substitutions
if args.port:
    bpf_text = bpf_text.replace('FILTER_PORT',
        'if (pkt_tuple.sport != %s && pkt_tuple.dport != %s) { return 0; }' % (args.port, args.port))
else:
    bpf_text = bpf_text.replace('FILTER_PORT', '')
    
if args.sample:
    bpf_text = bpf_text.replace('SAMPLING',
        'if (((pkt_tuple.seq + pkt_tuple.ack) << (32-%s) >> (32-%s)) != ((0x01 << %s) - 1)) { return 0;}' % (args.sample, args.sample, args.sample))
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
 

class ktime_t(ct.Structure):
    _fields_ = [
        ("total", ct.c_ulonglong),
        ("mac_in", ct.c_ulonglong),
        ("mac_in_timestamp", ct.c_ulonglong),
        ("ip_in", ct.c_ulonglong),
        ("tcp_in", ct.c_ulonglong),
        ("app", ct.c_ulonglong),
        ("tcp_out", ct.c_ulonglong),
        ("ip_out", ct.c_ulonglong),
        ("mac_out", ct.c_ulonglong),
        ("mac_out_timestamp", ct.c_ulonglong),
    ]


class Data_t(ct.Structure):
    _fields_ = [
        ("saddr", ct.c_uint),
        ("daddr", ct.c_uint),
        ("sport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("seq", ct.c_uint),
        ("ack", ct.c_uint),
        ("latencies", ktime_t),
    ]


tm = Time()
ip = gethostbyname(gethostname())

# process event
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_t)).contents
    print("5 %-20s -> %-20s %-12s %-12s %-10s %-10s %-10s %-10s %-10s %-10s %-10s %-10s" % (
        "%s:%d" % (ip, event.sport),
        "%s:%d" % (inet_ntop(AF_INET, pack('I', event.daddr)), event.dport),
        "%d" % (event.seq),
        "%d" % (event.ack),
        #"%f" % (tm.get_abs_time(event.latencies.mac_in_timestamp*1e-9)),
        #"%f" % (tm.get_abs_time(event.latencies.mac_out_timestamp*1e-9)),
        "%d" % (event.latencies.total/1000),
        "%d" % (event.latencies.mac_in/1000),
        "%d" % (event.latencies.ip_in/1000),
        "%d" % (event.latencies.tcp_in/1000),
        "%d" % (event.latencies.app/1000),
        "%d" % (event.latencies.tcp_out/1000),
        "%d" % (event.latencies.ip_out/1000),
        "%d" % (event.latencies.mac_out/1000)))


# initialize BPF
b = BPF(text=bpf_text)
trace_prefix = "trace_"
kprobe_functions_list = ["eth_type_trans", "ip_rcv", "tcp_v4_rcv", "skb_copy_datagram_iter", "tcp_transmit_skb", "ip_queue_xmit", "dev_queue_xmit", "dev_hard_start_xmit"]

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
    print("5 %-20s -> %-20s %-12s %-12s %-10s %-10s %-10s %-10s %-10s %-10s %-10s %-10s" % ("SADDR:SPORT", "DADDR:DPORT", "SEQ", "ACK", "TOTAL", "MAC_IN", "IP_IN", "TCP_IN", "APP", "TCP_OUT", "IP_OUT", "MAC_OUT"))

# read events
b["timestamp_events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        kill(getpid(), SIGKILL)
