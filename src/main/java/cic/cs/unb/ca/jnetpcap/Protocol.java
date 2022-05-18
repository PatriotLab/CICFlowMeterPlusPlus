package cic.cs.unb.ca.jnetpcap;

import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.vpn.L2TP;

public record Protocol(Tcp tcp, Http http, Udp udp, Ip4 ipv4, Ip6 ipv6, L2TP l2tp, Ethernet ethernet) {
	public Protocol(){
		this(new Tcp(), new Http(), new Udp(), new Ip4(), new Ip6(), new L2TP(), new Ethernet());
	}
}
