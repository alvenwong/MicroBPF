This file gives examples to leverage perf to trace events when receiving or transmitting packets in virtual machines. 
It helps BCC probe TCP metrics from these kernel functions. <p>

# Platform
Amazon AWS EC2

# Kernel
4.14.67-66.56.amzn1.x86_64

# perf installation 
Centos: yum install perf <br>
Ubuntu: apt install linux-tools-generic

# perf path
/sys/kernel/debug/tracing/

## perf files
cd /sys/kernel/debug/tracing/ <br>
available_events: include all the perf events in the kernel <br>
events/: trace event categories, such as net and kprobes

# Examples
## kprobes 
### cmd
perf trace --no-syscalls --event 'kprobes:*' wget www.google.com -O /dev/null
### event names for transmitting packets
eth_type_trans <br>
ip_rcv <br>
tcp_v4_rcv <br>
skb_copy_datagram_iter

### event names for receiving packets
__tcp_transmit_skb <br>
ip_queue_xmit <br>
dev_queue_xmit <br>
sch_direct_xmit

## net
### cmd 
perf trace --no-syscalls --event 'net:*' wget www.google.com -O /dev/null
### event names
net_dev_start_xmit <br>
net_dev_xmit <br>
net_dev_queue
