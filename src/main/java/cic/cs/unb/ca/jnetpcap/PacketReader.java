package cic.cs.unb.ca.jnetpcap;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapClosedException;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JHeaderPool;
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

				 packetInfo = PacketReader.getBasicPacketInfo(packet, readIP4, readIP6);
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

	public static BasicPacketInfo getBasicPacketInfo(PcapPacket packet,boolean readIP4, boolean readIP6) {
		BasicPacketInfo packetInfo = null;

		Protocol protocol = new Protocol();


		
		if(readIP4){					 
			packetInfo = getIpv4Info(packet,protocol);
			if (packetInfo == null && readIP6){
				packetInfo = getIpv6Info(packet,protocol);				 	
			}					 
		}else if(readIP6){
			packetInfo = getIpv6Info(packet,protocol);
			if (packetInfo == null && readIP4){
				packetInfo = getIpv4Info(packet,protocol);
			}z
		}
		
		if (packetInfo == null){
			packetInfo = getVPNInfo(packet,protocol,readIP4,readIP6);
		}
		
		return packetInfo;
	}

	private static BasicPacketInfo getVPNInfo(PcapPacket packet,Protocol protocol,boolean readIP4, boolean readIP6) {
		BasicPacketInfo packetInfo = null;
		try {
			packet.scan(L2TP.ID);
			
			if (packet.hasHeader(protocol.getL2tp())){
		    	if(readIP4){		
		    		packet.scan(protocol.getIpv4().getId());
		    		packetInfo = getIpv4Info(packet,protocol);
		    		if (packetInfo == null && readIP6){
		    			packet.scan(protocol.getIpv6().getId());
		    			packetInfo = getIpv6Info(packet,protocol);				 	
		    		}					 
		    	}else if(readIP6){
		    		packet.scan(protocol.getIpv6().getId());
		    		packetInfo = getIpv6Info(packet,protocol);
		    		if (packetInfo == null && readIP4){
		    			packet.scan(protocol.getIpv4().getId());
		    			packetInfo = getIpv4Info(packet,protocol);
		    		}
		    	}				

			}
		} catch (Exception e) {
			/*
			 * BufferUnderflowException while decoding header
			 * havn't fixed, so do not e.printStackTrace() 
			 */
			//e.printStackTrace();
			/*packet.scan(protocol.l2tp.getId());
			String errormsg = "";
			errormsg+=e.getMessage()+"\n";
			//errormsg+=packet.getHeader(new L2TP())+"\n";
			errormsg+="********************************************************************************"+"\n";
			errormsg+=packet.toHexdump()+"\n";
			logger.error(errormsg);*/
			return null;
		}
		
		return packetInfo;
	}

	private static BasicPacketInfo getIpv6Info(PcapPacket packet,Protocol protocol) {
		BasicPacketInfo packetInfo = null;
		try{
			if(packet.hasHeader(protocol.getIpv6())){
				packetInfo = new BasicPacketInfo();
				packetInfo.setSrc(protocol.getIpv6().source());
				packetInfo.setDst(protocol.getIpv6().destination());
				packetInfo.setTimeStamp(packet.getCaptureHeader().timestampInMicros());
				packetInfo.ttl = protocol.getIpv6().hopLimit();
				
				if(packet.hasHeader(protocol.getTcp())){
					packetInfo.setSrcPort(protocol.getTcp().source());
					packetInfo.setDstPort(protocol.getTcp().destination());
					packetInfo.setPayloadBytes(protocol.getTcp().getPayloadLength());
					packetInfo.setHeaderBytes(protocol.getTcp().getHeaderLength());
					packetInfo.setProtocol(6);
				}else if(packet.hasHeader(protocol.getUdp())) {
					packetInfo.setSrcPort(protocol.getUdp().source());
					packetInfo.setDstPort(protocol.getUdp().destination());
					packetInfo.setPayloadBytes(protocol.getUdp().getPayloadLength());
					packetInfo.setHeaderBytes(protocol.getUdp().getHeaderLength());
					packetInfo.setProtocol(17);
				}
			}
		}catch(Exception e){
			/*
			 * BufferUnderflowException while decoding header
			 * havn't fixed, so do not e.printStackTrace()
			 */
			//e.printStackTrace();
			/*packet.scan(protocol.ipv6.getId());
			String errormsg = "";
			errormsg+=e.getMessage()+"\n";
			//errormsg+=packet.getHeader(new Ip6())+"\n";
			errormsg+="********************************************************************************"+"\n";
			errormsg+=packet.toHexdump()+"\n";
			logger.error(errormsg);
			//System.exit(-1);*/
			return null;			
		}
				
		return packetInfo;
	}

	private static BasicPacketInfo getIpv4Info(PcapPacket packet,Protocol protocol) {
		BasicPacketInfo packetInfo = null;		
		try {
						
			if (packet.hasHeader(protocol.getIpv4())){
				packetInfo = new BasicPacketInfo();
				packetInfo.setSrc(protocol.getIpv4().source());
				packetInfo.setDst(protocol.getIpv4().destination());
				packetInfo.setTimeStamp(packet.getCaptureHeader().timestampInMicros());
				packetInfo.ttl = protocol.getIpv4().ttl();
				
				/*if(this.firstPacket == 0L)
					this.firstPacket = packet.getCaptureHeader().timestampInMillis();
				this.lastPacket = packet.getCaptureHeader().timestampInMillis();*/

				if(packet.hasHeader(protocol.getTcp())){
					packetInfo.setTCPWindow(protocol.getTcp().window());
					packetInfo.setSrcPort(protocol.getTcp().source());
					packetInfo.setDstPort(protocol.getTcp().destination());
					packetInfo.setProtocol(6);
					packetInfo.setFlagFIN(protocol.getTcp().flags_FIN());
					packetInfo.setFlagPSH(protocol.getTcp().flags_PSH());
					packetInfo.setFlagURG(protocol.getTcp().flags_URG());
					packetInfo.setFlagSYN(protocol.getTcp().flags_SYN());
					packetInfo.setFlagACK(protocol.getTcp().flags_ACK());
					packetInfo.setFlagECE(protocol.getTcp().flags_ECE());
					packetInfo.setFlagCWR(protocol.getTcp().flags_CWR());
					packetInfo.setFlagRST(protocol.getTcp().flags_RST());
					packetInfo.setPayloadBytes(protocol.getTcp().getPayloadLength());
					packetInfo.setHeaderBytes(protocol.getTcp().getHeaderLength());
				}else if(packet.hasHeader(protocol.getUdp())){
					packetInfo.setSrcPort(protocol.getUdp().source());
					packetInfo.setDstPort(protocol.getUdp().destination());
					packetInfo.setPayloadBytes(protocol.getUdp().getPayloadLength());
					packetInfo.setHeaderBytes(protocol.getUdp().getHeaderLength());
					packetInfo.setProtocol(17);
				} else {
					int headerCount = packet.getHeaderCount();
					for(int i=0;i<headerCount;i++) {
						JHeader header = JHeaderPool.getDefault().getHeader(i);
						//JHeader hh = packet.getHeaderByIndex(i, header);
						//logger.debug("getIpv4Info: {} --description: {} ",header.getName(),header.getDescription());
					}
				}
			}
		} catch (Exception e) {
			/*
			 * BufferUnderflowException while decoding header
			 * havn't fixed, so do not e.printStackTrace()
			 */
			//e.printStackTrace();
			/*packet.scan(protocol.ipv4.getId());
			String errormsg = "";
			errormsg+=e.getMessage()+"\n";
			//errormsg+=packet.getHeader(new Ip4())+"\n";
			errormsg+="********************************************************************************"+"\n";
			errormsg+=packet.toHexdump()+"\n";
			logger.error(errormsg);
			return null;*/
		}
		
		return packetInfo;
	}
}
