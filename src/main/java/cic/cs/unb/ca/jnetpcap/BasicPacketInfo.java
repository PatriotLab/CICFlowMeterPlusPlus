package cic.cs.unb.ca.jnetpcap;

import org.jnetpcap.packet.format.FormatUtils;

import java.util.Arrays;

public class BasicPacketInfo {
	
/*  Basic Info to generate flows from packets  	*/
    private    byte[] src;
    private    byte[] dst;
    private    int srcPort;
    private    int dstPort;
    private    int protocol;
    private    long   timeStamp;
    private    long   payloadBytes;
    private    String  flowId = null;  
/* ******************************************** */    
    private    boolean flagFIN = false;
	private    boolean flagPSH = false;
	private    boolean flagURG = false;
	private    boolean flagECE = false;
	private    boolean flagSYN = false;
	private    boolean flagACK = false;
	private    boolean flagCWR = false;
	private    boolean flagRST = false;
	private	   int TCPWindow=0;
	private	   long headerBytes;
	private int payloadPacket=0;


	public boolean isBwdPacket = false;

//	public BasicPacketInfo(byte[] src, byte[] dst, int srcPort, int dstPort,
//			int protocol, long timeStamp, IdGenerator generator) {
//		super();
//		this.id = generator.nextId();
//		this.src = src;
//		this.dst = dst;
//		this.srcPort = srcPort;
//		this.dstPort = dstPort;
//		this.protocol = protocol;
//		this.timeStamp = timeStamp;
//		generateFlowId();
//	}
	
    public BasicPacketInfo() {
		super();
	}

 	public String fwdFlowId() {  
		this.flowId = this.getSourceIP() + "-" + this.getDestinationIP() + "-" + this.srcPort  + "-" + this.dstPort  + "-" + this.protocol;
		return this.flowId;
	}
	
	public String bwdFlowId() {  
		this.flowId = this.getDestinationIP() + "-" + this.getSourceIP() + "-" + this.dstPort  + "-" + this.srcPort  + "-" + this.protocol;
		return this.flowId;
	}

	public String dumpInfo() {
		return null;
	}
	public int getPayloadPacket() {
		return payloadPacket+=1;
	}

    public String getSourceIP(){
    	return FormatUtils.ip(this.src);
    }

    public String getDestinationIP(){
    	return FormatUtils.ip(this.dst);
    }

	public byte[] getSrc() {
		return Arrays.copyOf(src,src.length);
	}

	public void setSrc(byte[] src) {
		this.src = src;
	}

	public byte[] getDst() {
		return Arrays.copyOf(dst,dst.length);
	}

	public void setDst(byte[] dst) {
		this.dst = dst;
	}

	public int getSrcPort() {
		return srcPort;
	}

	public void setSrcPort(int srcPort) {
		this.srcPort = srcPort;
	}

	public int getDstPort() {
		return dstPort;
	}

	public void setDstPort(int dstPort) {
		this.dstPort = dstPort;
	}

	public int getProtocol() {
		return protocol;
	}

	public void setProtocol(int protocol) {
		this.protocol = protocol;
	}

	public long getTimeStamp() {
		return timeStamp;
	}

	public void setTimeStamp(long timeStamp) {
		this.timeStamp = timeStamp;
	}

	public void setFlowId(String flowId) {		
		this.flowId = flowId;
	}

	public boolean isForwardPacket(byte[] sourceIP) {
		return Arrays.equals(sourceIP, this.src);
	}

	public boolean isForwardPacket() {
		return !isBwdPacket;
	}

	public long getPayloadBytes() {
		return payloadBytes;
	}

	public void setPayloadBytes(long payloadBytes) {
		this.payloadBytes = payloadBytes;
	}

	public long getHeaderBytes() {
		return headerBytes;
	}

	public void setHeaderBytes(long headerBytes) {
		this.headerBytes = headerBytes;
	}

	public boolean hasFlagFIN() {
		return flagFIN;
	}

	public void setFlagFIN(boolean flagFIN) {
		this.flagFIN = flagFIN;
	}

	public boolean hasFlagPSH() {
		return flagPSH;
	}

	public void setFlagPSH(boolean flagPSH) {
		this.flagPSH = flagPSH;
	}

	public boolean hasFlagURG() {
		return flagURG;
	}

	public void setFlagURG(boolean flagURG) {
		this.flagURG = flagURG;
	}

	public boolean hasFlagECE() {
		return flagECE;
	}

	public void setFlagECE(boolean flagECE) {
		this.flagECE = flagECE;
	}

	public boolean hasFlagSYN() {
		return flagSYN;
	}

	public void setFlagSYN(boolean flagSYN) {
		this.flagSYN = flagSYN;
	}

	public boolean hasFlagACK() {
		return flagACK;
	}

	public void setFlagACK(boolean flagACK) {
		this.flagACK = flagACK;
	}

	public boolean hasFlagCWR() {
		return flagCWR;
	}

	public void setFlagCWR(boolean flagCWR) {
		this.flagCWR = flagCWR;
	}

	public boolean hasFlagRST() {
		return flagRST;
	}

	public void setFlagRST(boolean flagRST) {
		this.flagRST = flagRST;
	}

	public int getTCPWindow(){
		return TCPWindow;
	}

	public void setTCPWindow(int TCPWindow){
		this.TCPWindow = TCPWindow;
	}
}
