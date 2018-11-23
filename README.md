# Introduce
This project leverages eBPF ([BCC](https://github.com/iovisor/bcc)) to capture TCP metrics from the kernel for performance diagnosis in microservices architectures. It probes two levels of statistics: flows and packets. The flow-level statistics currently have sixteen metrics, such as flight size, CWnd, sampled RTT, number of fast retransmission and timeout. The packet-level statistics are the breakdown of RTT, including latencies in TCP layer, IP layer, MAC layer, and the network (from NIC to NIC). It also measure the application layer latencies.

# Flow-level Statistics
Most of the following flow-level statistics are collected from [SNAP](https://www.microsoft.com/en-us/research/wp-content/uploads/2011/01/nsdi11_dcmeasurement.pdf) (NSDI'11) and [NetPoiror](http://netdb.cis.upenn.edu/papers/netpoirot.pdf) (SIGCOMM'16). <p>
<table>
  <tr>
    <th>Index</th>
    <th>Statistics</th>
    <th>Definition</th>
  </tr>
  <tr>
    <td>1</td>
    <td>FlightSize</td>
    <td>Packets sent but not ACKed</td>
   </tr>
    <tr>
    <td>2</td>
    <td>RWND</td>
    <td>Receive window size</td>
   </tr>
    <tr>
    <td>3</td>
    <td>CWND</td>
    <td>Congestion window size</td>
   </tr>
    <tr>
    <td>4</td>
    <td>MSS</td>
    <td>Maximum segment size</td>
   </tr>
    <tr>
    <td>5</td>
    <td>RePackets</td>
    <td>Retransmitted packets</td>
   </tr>
    <tr>
    <td>6</td>
    <td>BSent</td>
    <td>Number of bytes sent</td>
   </tr>
   </tr>
    <tr>
    <td>7</td>
    <td>BReceived</td>
    <td>Number of bytes received</td>
   </tr>
   </tr>
    <tr>
    <td>8</td>
    <td>fastRetrans</td>
    <td>Number of fast restransmission</td>
   </tr>
   </tr>
    <tr>
    <td>9</td>
    <td>Timeout</td>
    <td>Number of timeout</td>
   </tr>
   </tr>
    <tr>
    <td>10</td>
    <td>CurAppWQueue</td>
    <td>Number of bytes in the send buffer</td>
   </tr>
   </tr>
    <tr>
    <td>11</td>
    <td>MaxAppWQueue</td>
    <td>Max CurAppWQueue</td>
   </tr>
   <tr>
    <td>12</td>
    <td>SampleRTT</td>
    <td>Total number of RTT samples</td>
   </tr>
   <tr>
    <td>13</td>
    <td>SumRTT</td>
    <td>Sum of RTTs that TCP samples</td>
   </tr>
   <tr>
    <td>14</td>
    <td>ReadByte</td>
    <td>Number of bytes when the socket makes a read call</td>
   </tr>
   <tr>
    <td>15</td>
    <td>WriteByte</td>
    <td>Number of bytes when the socket makes a write call</td>
   </tr>
   <tr>
    <td>16</td>
    <td>Duration</td>
    <td>Duration in which connection has been open</td>
   </tr>
</table>


# Packet-level Statistics

## Overview
MicroBPF aims to measure the latencies in different layers. This figure shows the overview of MicroBPF. <p>
<img align="center" src="https://github.com/alvenwong/MicroBPF/blob/master/figures/uBPF_overview.png" width="600"> <p>
  
Given a Request R generated from the sender. It will traverse the networking stack and depart the NIC of the sender. After going through the network, it arrives at the NIC of the receiver and traverse its networking stack. Then the application will process this request and return the Response R back to the sender. <p>
The table displays the latencies measured by MicroBPF in different layers. <p>
<table>
  <tr>
    <th>Layer</th>
    <th>Latencies</th>
  </tr>
  <tr>
    <td>TCP</td>
    <td>L_TCP_1, L_TCP_2, L_TCP_3, L_TCP_4</td>
  <tr>
  <tr>
    <td>IP</td>
    <td>L_IP_1, L_IP_2, L_IP_3, L_IP_4</td>
  <tr>
  <tr>
    <td>MAC</td>
    <td>L_NIC_1, L_NIC_2, L_NIC_3, L_NIC_4</td>
  <tr>
  <tr>
    <td>Network</td>
    <td>L_NET_1, L_NET_2</td>
  <tr>
  <tr>
    <td>APP</td>
    <td>L_APP_1, L_APP_2</td>
  <tr>
</table>

## Receiving packets
This table shows the kernel functions for probing latencies when receiving packets.<p> 
<table>
  <tr>
    <th>Layer</th>
    <th>Start Function </th>
    <th>End Function </th>
  </tr>
  <tr>
    <td>MAC Layer</td>
    <td>eth_type_trans() </td>
    <td>ip_rcv() </td>
  </tr>
  <tr>
    <td>IP Layer</td>
    <td>ip_rcv() </td>
    <td>tcp_v4_rcv() </td>
  </tr>
  <tr>
    <td>TCP Layer</td>
    <td>tcp_v4_rcv() </td>
    <td>skb_copy_datagram_iter() </td>
  </tr>
</table>

## Transmitting packets
This table shows the kernel functions for probing latencies when transmitting packets.<p> 
<table>
  <tr>
    <th>Layer</th>
    <th>Start Function </th>
    <th>End Function </th>
  </tr>
  <tr>
    <td>TCP Layer</td>
    <td>tcp_transmit_skb() </td>
    <td>ip_queue_xmit() </td>
  </tr>
  <tr>
    <td>IP Layer</td>
    <td>ip_queue_xmit() </td>
    <td>dev_queue_xmit() </td>
  </tr>
  <tr>
    <td>MAC Layer</td>
    <td>dev_queue_xmit() </td>
    <td>dev_hard_start_xmit() </td>
  </tr>
  <tr>
    <td>QDISC Layer*</td>
    <td>  </td>
    <td>  </td>
  </tr>
</table>
* Currently, uBPF is just deployed on AWS EC2 instances. The default setting of EC2 VMs has no QDISC layer. <p>
<br>
  
## The network latency
To measure the network latency in VMs, uBPF timestamps SKB in eth_type_trans()/dev_hard_start_xmit() and sends the metrics to a measurement node to calculate the network latency. A better way to measure the network latency is to timestamp in the physical NIC driver, while there is no physical NIC driver in the AWS VMs. We will add this feature for physical machines soon. <p>
The figure shows the system design of MicroBPF to measure the network latencies. <p>
<img align="center" src="https://github.com/alvenwong/MicroBPF/blob/master/figures/Network_latencies_design.png" width="500"> <p>
  
## The application layer latency
This table shows the kernel functions for measuring the application layer latencies.<p> 
  
<table>
  <tr>
    <th>Side</th>
    <th>Ideal trace point</th>
    <th>Practical trace point</th>
  </tr>
  <tr>
    <td>Receive</td>
    <td>recv()</td>
    <td>skb_copy_datagram_iter()</td>
  </tr>
  <tr>
    <td>Transmit</td>
    <td>send()</td>
    <td>tcp_transmit_skb()</td>
  </tr>
</table>

# Preliminary evaluations
## Testbed
We launched two AWS EC2 instances, each with only one CPU core. One is running the Apache server (VM B) and the other is running the Apache benchmark (VM A). The number of concurrent connections is 10.
## Preliminary results
This figure shows the network latencies and RTTs from A (Apache Benchmark) to B (Apache Server). The TCP layer latency is measured in VM B. We can see that the network latency is stable (around 1000 us) while the TCP layer latency and RTT are both greatly fluctuating and have the similar CDF. That is because that the network stack process ACKs in the TCP layer. On the sender side, the stack timestamps an SKB when it is transmitted to the IP layer. While on the receiver side, the stack has to process the SKB in the TCP layer and then return the ACK. The kernel scheduling in the TCP layer will significantly affect RTTs. <p>

<img align="center" src="https://github.com/alvenwong/MicroBPF/blob/master/figures/B_TCP_layer.png" width="450" title="From A to B"> <p>

Similarly, the next figure is the preliminary results from B to A. The TCP layer latency is measured in VM A (benchmark) and is quite small. The network latency is stable (around 550 us), while RTT is still fluctuating.
<img src="https://github.com/alvenwong/MicroBPF/blob/master/figures/A_TCP_layer.png" width="450" title="From B to A"> <p>

We argue that it may provide a new prospective for performance diagnosis, system monitoring and congestion control in data centers if we split RTTs into the kernel latencies and the network latencies. <p>
  
# BCC files
tcpin.py: trace the received packets in the kernel. <br>
tcpout.py: trace the transmitted packets in the kernel. <br>
tcpack.py: trace flow-level metrics triggered by ACKs. <br>
app.py: measure the application layer latency. <br>
tcp.py: measure the latencies in different layers in hosts, i.e., the combination of tcpin.py, tcpout.py and app.py. <br>
tcpsock.py: just an example to probe ReadByte and WriteByte. <br>
clock.py: Clock synchronization for uBPF. <br>
nic/: files for measuring the network latencies. <br>  
  
# Kernel Functions Probe
Refer to [perf.md](https://github.com/alvenwong/kernel_trace/blob/master/perf.md).

# Main functions in network stack
Refer to [network_kernel.md](https://github.com/alvenwong/docs/blob/master/network_kernel.md).

# How to run 
Refer to [docker.md](https://github.com/alvenwong/kernel_trace/blob/master/docker.md).

# Container
Refer to [docker.md](https://github.com/alvenwong/kernel_trace/blob/master/docker.md).

# Test Examples
Refer to [test_example.md](https://github.com/alvenwong/kernel_trace/blob/master/test_example.md)
