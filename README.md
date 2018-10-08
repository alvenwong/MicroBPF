# Introduce
This project leverages eBPF (BCC) to capture TCP metrics from the kernel for performance diagnosis in microservices architectures. It probes two levels of statistics: flows and packets.  The flow-level statistics currently have sixteen metrics, such as flight size, CWnd, sampled RTT, number of fast retransmission and timeout. The packets-level statistics are the breakdown of the end-to-end delay, including latencies in TCP layer, IP layer and kernel space.

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
This part of statistics is the breakdown of end-to-end delay, including latencies in TCP layer, IP layer and the latency from IP layer to dirver.

# BCC files
in_probe.py: trace the received packets in the kernel. <br>
out_probe.py: trace the transmitted packets in the kernel. <br>
tcpack.py: trace flow-level metrics triggered by ACKs. <br>
tcpsock: probe ReadByte and WriteByte <br>
  
# Kernel Functions Probe
Refer to [perf.md](https://github.com/alvenwong/kernel_trace/blob/master/perf.md)
  
# Container
Refer to [docker.md](https://github.com/alvenwong/kernel_trace/blob/master/docker.md)

# Test Examples
Refer to [test_example.md](https://github.com/alvenwong/kernel_trace/blob/master/test_exampe.md)
