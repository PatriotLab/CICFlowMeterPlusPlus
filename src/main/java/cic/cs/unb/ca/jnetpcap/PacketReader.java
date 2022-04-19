package cic.cs.unb.ca.jnetpcap;

import cic.cs.unb.ca.jnetpcap.features.TCPFlags;
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
	
	public PacketReader(String filename, boolean readip4, boolean readip6) {
		super();
		this.readIP4 = readip4;
		this.readIP6 = readip6;
		this.config(filename);
	}	
	
	private void config(String filename){
        file = filename;
		StringBuilder errbuf = new StringBuilder(); // For any error msgs
		pcapReader = Pcap.openOffline(filename, errbuf);
		
		this.firstPacket = 0L;
		this.lastPacket = 0L;

		if (pcapReader == null) {
			logger.error("Error while opening file for capture: "+errbuf.toString());
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
			 logger.debug("Read All packets on {}",file);
			 throw e;
		 }catch(Exception ex){
			 logger.debug(ex.getMessage());
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

	public static BasicPacketInfo getBasicPacketInfo(PcapPacket packet,boolean readIP4, boolean readIP6, Protocol protocol) {
		try {
			BasicPacketInfo packetInfo = new BasicPacketInfo();

			packetInfo.setTimeStamp(packet.getCaptureHeader().timestampInMicros());

//			Protocol protocol = new Protocol();

			// Packet info reading goes in order from the lowest layer to the highest layer

			// Start with Layer 2 protocols
			if (packet.hasHeader(protocol.getL2tp())) {
				packet.scan(L2TP.ID);
			}
			if (packet.hasHeader(protocol.getEthernet())) {
				packetInfo.setSrcMac(protocol.getEthernet().source());
				packetInfo.setDstMac(protocol.getEthernet().destination());
			}

			// Layer 3 protocols
			if (readIP4 && packet.hasHeader(protocol.getIpv4())) {
				packetInfo.setSrc(protocol.getIpv4().source());
				packetInfo.setDst(protocol.getIpv4().destination());
				packetInfo.ttl = protocol.getIpv4().ttl();
			} else if (readIP6 && packet.hasHeader(protocol.getIpv6())) {
				packetInfo.setSrc(protocol.getIpv6().source());
				packetInfo.setDst(protocol.getIpv6().destination());
				packetInfo.ttl = protocol.getIpv6().hopLimit();
			} else {
				return null; // Non-IP packets should be ignored
			}

			// Layer 4 protocols
			if (packet.hasHeader(protocol.getTcp())) {
				packetInfo.setSrcPort(protocol.getTcp().source());
				packetInfo.setDstPort(protocol.getTcp().destination());

				packetInfo.setTcpFlags(BasicPacketInfo.TCPFlags.from_tcp_header(protocol.getTcp()));

				packetInfo.setPayloadBytes(protocol.getTcp().getPayloadLength());
				packetInfo.setHeaderBytes(protocol.getTcp().getHeaderLength());
				packetInfo.setProtocol(6);

				packetInfo.setTCPWindow(protocol.getTcp().window());
			} else if (packet.hasHeader(protocol.getUdp())) {
				packetInfo.setSrcPort(protocol.getUdp().source());
				packetInfo.setDstPort(protocol.getUdp().destination());
				packetInfo.setPayloadBytes(protocol.getUdp().getPayloadLength());
				packetInfo.setHeaderBytes(protocol.getUdp().getHeaderLength());
				packetInfo.setProtocol(17);
			}

			// Layer 5 and beyond would go here

			return packetInfo;
		} catch (Exception e){
			logger.error("Error in reading packet info", e);

			return null;
		}
	}
}
