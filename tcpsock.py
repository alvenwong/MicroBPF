#!/usr/bin/env python

from __future__ import print_function
from bcc import BPF
from socket import inet_ntop, AF_INET
#import ctypes as ct
import signal
from time import sleep, strftime
from struct import pack


bpf_text = """
#include <uapi/linux/ptrace.h>
#define KBUILD_MODNAME "foo"
#include <uapi/linux/tcp.h>
#include <uapi/linux/ip.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <bcc/proto.h>

struct flow_tuple {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

struct flow_info {
    u64 readBytes; 
    u64 writeBytes;
};

BPF_HASH(ipv4_flows, struct flow_tuple, struct flow_info);


int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
    struct msghdr *msg, size_t size)
{
    if (sk == NULL)
        return 0;

    u16 dport = 0;
    // pull in details from the packet headers and the sock struct
    u16 family = sk->__sk_common.skc_family;
    if (family == AF_INET) {
        struct flow_tuple flow = {};
        flow.saddr = sk->__sk_common.skc_rcv_saddr;
        flow.daddr = sk->__sk_common.skc_daddr;
        flow.sport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        flow.dport = ntohs(dport);
        
        // struct tcp_sock *tp = (struct tcp_sock *)sk;

        // if (flow.sport == 5205 || flow.dport == 5205) {
        struct flow_info *finfo, zero = {};
        finfo = ipv4_flows.lookup_or_init(&flow, &zero);
        finfo->writeBytes += size;
        // }
    }
    return 0;
}

/*
 * tcp_recvmsg() would be obvious to trace, but is less suitable because:
 * - we'd need to trace both entry and return, to have both sock and size
 * - misses tcp_read_sock() traffic
 * we'd much prefer tracepoints once they are available.
 */
int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied)
{
    u16 dport = 0, family = sk->__sk_common.skc_family;

    if (copied <= 0)
        return 0;

    if (family == AF_INET) {
        struct flow_tuple flow = {};
        flow.saddr = sk->__sk_common.skc_rcv_saddr;
        flow.daddr = sk->__sk_common.skc_daddr;
        flow.sport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        flow.dport = ntohs(dport);
        
        // struct tcp_sock *tp = (struct tcp_sock *)sk;

        // if (flow.sport == 5205 || flow.dport == 5205) {
        struct flow_info *finfo, zero = {};
        finfo = ipv4_flows.lookup_or_init(&flow, &zero);
        finfo->readBytes += copied;
        // }
    }
    return 0;
}
"""

# initialize BPF
b = BPF(text = bpf_text)
# flows_info = b["ipv4_flows"]

interval = 1
print("Tracing... Output every %d seconds. Hit ctl+c to end" % (interval))

exiting  = 0
while 1:
    try:
        sleep(interval)
    except KeyboardInterrupt:
        exiting = 1

    flows_info = b.get_table("ipv4_flows")
    for k, v in flows_info.items():
        print("%-14s %-5d %-14s %-5d %-8uKB %-8uKB" % (inet_ntop(AF_INET, pack('I', k.saddr)), k.sport, inet_ntop(AF_INET, pack('I', k.daddr)), k.dport, v.writeBytes / 1024, v.readBytes / 1024))
    #flows_info.clear()

    if exiting == 1:
       exit() 
