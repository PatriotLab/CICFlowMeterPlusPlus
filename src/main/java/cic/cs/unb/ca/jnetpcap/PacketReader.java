package cic.cs.unb.ca.jnetpcap;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapClosedException;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.vpn.L2TP;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PacketReader {

	private static final Logger logger = LoggerFactory.getLogger(PacketReader.class);
	private Pcap pcapReader;
	
	private long firstPacket;
	private long lastPacket;

	private PcapHeader hdr;
	private JBuffer buf;
	
	private final boolean readIP6;
	private final boolean readIP4;
	private String file;
	private final Protocol protocol = new Protocol();



	public PacketReader(String filename) {
		super();	
		this.readIP4 = true;
		this.readIP6 = false;
		this.config(filename);
	}

	public PacketReader(boolean ip4, boolean ip6){
		super();
		this.readIP4 = ip4;
		this.readIP6 = ip6;
	}
	
	public PacketReader(String filename, boolean readip4, boolean readip6) {
		super();
		this.readIP4 = readip4;
		this.readIP6 = readip6;
		this.config(filename);
	}

	public static PacketReader fromLive(String interface_name, boolean ip4, boolean ip6){
		PacketReader reader = new PacketReader(ip4, ip6);
		reader.file = interface_name;

		StringBuilder errbuf = new StringBuilder();
		reader.pcapReader = Pcap.openLive(interface_name, 64 * 1024, Pcap.MODE_PROMISCUOUS, 60 * 1000, errbuf);

		if (reader.pcapReader == null) {
			throw new RuntimeException(String.format("Error while opening interface %s for capture: %s", interface_name, errbuf));
		}

		reader.firstPacket = 0L;
		reader.lastPacket = 0L;

		reader.hdr = new PcapHeader(JMemory.POINTER);
		reader.buf = new JBuffer(JMemory.POINTER);

		return reader;
	}

	private void config(String filename){
        file = filename;
		StringBuilder errbuf = new StringBuilder(); // For any error msgs
		pcapReader = Pcap.openOffline(filename, errbuf);
		
		this.firstPacket = 0L;
		this.lastPacket = 0L;

		if (pcapReader == null) {
			logger.error("Error while opening file for capture: "+errbuf);
			System.exit(-1);
		}else{
			hdr = new PcapHeader(JMemory.POINTER);
			buf = new JBuffer(JMemory.POINTER);		
		}		
	}
	
	public BasicPacketInfo nextPacket(){
		 PcapPacket      packet;
		 BasicPacketInfo packetInfo = null;
		 try{
			 if(pcapReader.nextEx(hdr,buf) == Pcap.NEXT_EX_OK){
				 packet = new PcapPacket(hdr, buf);
				 packet.scan(Ethernet.ID);

				 packetInfo = PacketReader.getBasicPacketInfo(packet, readIP4, readIP6, protocol);
			 }else{
				 throw new PcapClosedException();
			 }
		 }catch(PcapClosedException e){
//			 logger.error("Read All packets on {}",file);
			 throw e;
		 }catch(Exception ex){
			 logger.error(ex.getMessage());
		 }
		 return packetInfo;
	}

	public long getFirstPacket() {
		return firstPacket;
	}

	public void setFirstPacket(long firstPacket) {
		this.firstPacket = firstPacket;
	}

	public long getLastPacket() {
		return lastPacket;
	}

	public void setLastPacket(long lastPacket) {
		this.lastPacket = lastPacket;
	}

	public void closeReader(){
		this.pcapReader.close();
	}

	public static BasicPacketInfo getBasicPacketInfo(PcapPacket packet,boolean readIP4, boolean readIP6, Protocol protocol) {
		try {
			BasicPacketInfo packetInfo = new BasicPacketInfo();

			packetInfo.setTimeStamp(packet.getCaptureHeader().timestampInMicros());

//			Protocol protocol = new Protocol();

			// Packet info reading goes in order from the lowest layer to the highest layer

			// Start with Layer 2 protocols
			if (packet.hasHeader(protocol.l2tp())) {
				packet.scan(L2TP.ID);
			}
			if (packet.hasHeader(protocol.ethernet())) {
				packetInfo.setSrcMac(protocol.ethernet().source());
				packetInfo.setDstMac(protocol.ethernet().destination());
			}

			// Layer 3 protocols
			if (readIP4 && packet.hasHeader(protocol.ipv4())) {
				packetInfo.setSrc(protocol.ipv4().source());
				packetInfo.setDst(protocol.ipv4().destination());
				packetInfo.ttl = protocol.ipv4().ttl();
			} else if (readIP6 && packet.hasHeader(protocol.ipv6())) {
				packetInfo.setSrc(protocol.ipv6().source());
				packetInfo.setDst(protocol.ipv6().destination());
				packetInfo.ttl = protocol.ipv6().hopLimit();
			} else {
				return null; // Non-IP packets should be ignored
			}

			// Layer 4 protocols
			if (packet.hasHeader(protocol.tcp())) {
				packetInfo.setSrcPort(protocol.tcp().source());
				packetInfo.setDstPort(protocol.tcp().destination());

				packetInfo.setTcpFlags(BasicPacketInfo.TCPFlags.from_tcp_header(protocol.tcp()));

				packetInfo.setPayloadBytes(protocol.tcp().getPayloadLength());
				packetInfo.setHeaderBytes(protocol.tcp().getHeaderLength());
				packetInfo.setProtocol(6);

				packetInfo.setTCPWindow(protocol.tcp().window());
			} else if (packet.hasHeader(protocol.udp())) {
				packetInfo.setSrcPort(protocol.udp().source());
				packetInfo.setDstPort(protocol.udp().destination());
				packetInfo.setPayloadBytes(protocol.udp().getPayloadLength());
				packetInfo.setHeaderBytes(protocol.udp().getHeaderLength());
				packetInfo.setProtocol(17);
			}

			// Layer 7 Protocols
			//HTTP
			if(packet.hasHeader(protocol.http())) {
				packetInfo.isHTTP = true;
				if (protocol.http().isResponse()) {
					packetInfo.httpResponseHeader = protocol.http().getHeaderLength();
					packetInfo.httpResponsePayload = protocol.http().getPayloadLength();
					packetInfo.response_timestamp = packet.getCaptureHeader().timestampInMicros();
				} else if (!(protocol.http().isResponse())) {
					packetInfo.httpRequestHeader = protocol.http().getHeaderLength();
					packetInfo.httpRequestPayload = protocol.http().getPayloadLength();
					packetInfo.request_timestamp = packet.getCaptureHeader().timestampInMicros();
				}
			}
			return packetInfo;
		} catch (Exception e){
			logger.error("Error in reading packet info", e);

			return null;
		}
	}
}
