package cic.cs.unb.ca.jnetpcap;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

public final class BasicPacketInfo2 {
    final byte[] src;
    final byte[] dst;
    final int srcPort;
    final int dstPort;

    final long timestamp;
    final int totalBytes;
    final int headerBytes;
    final int payloadBytes;

    final int tcpWindow;
    final TCPFlags tcpFlags;

    final int protocol;

    final int ttl;

    BasicPacketInfo2(PcapPacket p){
        Ip4 ipv4 = new Ip4();
        Ip6 ipv6 = new Ip6();
        Tcp tcp = new Tcp();
        Udp udp = new Udp();

        timestamp = p.getCaptureHeader().timestampInMillis();
        totalBytes = p.getTotalSize();

        if(p.hasHeader(ipv4)){
            src = ipv4.source();
            dst = ipv4.destination();
            ttl = ipv4.ttl();
        } else if(p.hasHeader(ipv6)){
            src = ipv6.source();
            dst = ipv6.destination();

            byte[] ipv6_header_bytes = ipv6.getHeader();
            // TTL is 8th octet in IPv6 header
            ttl = ipv6_header_bytes[8];
        } else {
            throw new RuntimeException("Packet did not have IPv4 or IPv6");
        }

        if(p.hasHeader(tcp)){
            srcPort = tcp.source();
            dstPort = tcp.destination();
            headerBytes = tcp.getHeaderLength();
            payloadBytes = tcp.getPayloadLength();
            protocol = 17;

            tcpWindow = tcp.window();
            tcpFlags = new TCPFlags(tcp);
        } else if(p.hasHeader(udp)){
            srcPort = udp.source();
            dstPort = udp.destination();
            headerBytes = udp.getHeaderLength();
            payloadBytes = udp.getPayloadLength();
            protocol = 6;

            tcpWindow = 0;
            tcpFlags = new TCPFlags();
        } else {
            throw new RuntimeException("packet does not have UDP or TCP");
        }
    }

    public String fwdFlowId() {
        return FormatUtils.ip(src) + "-" + FormatUtils.ip(dst) + "-" + srcPort  + "-" + dstPort  + "-" + protocol;
    }

    public String bwdFlowId() {
        return FormatUtils.ip(dst) + "-" + FormatUtils.ip(src) + "-" + dstPort  + "-" + srcPort  + "-" + protocol;
    }

    static final class TCPFlags {
        public final boolean fin;
        public final boolean psh;
        public final boolean urg;
        public final boolean ece;
        public final boolean syn;
        public final boolean cwr;
        public final boolean rst;

        /**
         * Flags all set to false. Default values for if a packet is not TCP.
         */
        TCPFlags(){
            fin = false;
            psh = false;
            urg = false;
            ece = false;
            syn = false;
            cwr = false;
            rst = false;
        }

        /**
         * Flags set based on information from a TCP Packet.
         * @param tcp_info TCP information from JNetPcap
         */
        TCPFlags(Tcp tcp_info){
            fin = tcp_info.flags_FIN();
            psh = tcp_info.flags_PSH();
            urg = tcp_info.flags_URG();
            ece = tcp_info.flags_ECE();
            syn = tcp_info.flags_SYN();
            cwr = tcp_info.flags_CWR();
            rst = tcp_info.flags_RST();
        }
    }
}


