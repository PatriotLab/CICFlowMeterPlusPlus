package cic.cs.unb.ca.jnetpcap;

import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.tcpip.Tcp;

import java.util.Arrays;

public final class BasicPacketInfo {

    public record TCPFlags(boolean fin, boolean psh, boolean urg, boolean ece, boolean syn, boolean ack, boolean cwr,
                           boolean rst) {
        static TCPFlags all_false(){
            return new TCPFlags(
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false
            );
        }

        static TCPFlags from_tcp_header(Tcp header){
            return new TCPFlags(
                    header.flags_FIN(),
                    header.flags_PSH(),
                    header.flags_URG(),
                    header.flags_ECE(),
                    header.flags_SYN(),
                    header.flags_ACK(),
                    header.flags_CWR(),
                    header.flags_RST()
            );
        }
    }

    /*  Basic Info to generate flows from packets  	*/
    private byte[] src;
    private byte[] dst;
    private byte[] srcMac;
    private byte[] dstMac;
    private int srcPort;
    private int dstPort;
    private int protocol;
    private long timeStamp;
    private long payloadBytes;
    private String flowId = null;
    /* ******************************************** */
//    private boolean flagFIN = false;
//    private boolean flagPSH = false;
//    private boolean flagURG = false;
//    private boolean flagECE = false;
//    private boolean flagSYN = false;
//    private boolean flagACK = false;
//    private boolean flagCWR = false;
//    private boolean flagRST = false;
    private TCPFlags tcpFlags = TCPFlags.all_false();
    private int TCPWindow = 0;
    private long headerBytes;
    private int payloadPacket = 0;

    public boolean isBwdPacket = false;

    public int ttl = 0;

    public int httpRequestHeader = 0;
    public int httpRequestPayload = 0;

    public int httpResponseHeader = 0;
    public int httpResponsePayload = 0;
    public long request_timestamp = 0;
    public long response_timestamp = 0;
    public long IAT_time;
    public boolean isHTTP;

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
        this.flowId = this.getSourceIP() + "-" + this.getDestinationIP() + "-" + this.srcPort + "-" + this.dstPort + "-" + this.protocol;
        return this.flowId;
    }

    public String bwdFlowId() {
        this.flowId = this.getDestinationIP() + "-" + this.getSourceIP() + "-" + this.dstPort + "-" + this.srcPort + "-" + this.protocol;
        return this.flowId;
    }

    public String dumpInfo() {
        return null;
    }

    public int getPayloadPacket() {
        return payloadPacket += 1;
    }

    public String getSourceIP() {
        return FormatUtils.ip(this.src);
    }

    public String getDestinationIP() {
        return FormatUtils.ip(this.dst);
    }

    public byte[] getSrc() {
        return Arrays.copyOf(src, src.length);
    }

    public void setSrc(byte[] src) {
        this.src = src;
    }

    public byte[] getDst() {
        return Arrays.copyOf(dst, dst.length);
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
        return this.tcpFlags.fin;
    }

    public boolean hasFlagPSH() {
        return this.tcpFlags.psh;
    }

    public boolean hasFlagURG() {
        return this.tcpFlags.urg;
    }

    public boolean hasFlagECE() {
        return this.tcpFlags.ece;
    }

    public boolean hasFlagSYN() {
        return this.tcpFlags.syn;
    }

    public boolean hasFlagACK() {
        return this.tcpFlags.ack;
    }

    public boolean hasFlagCWR() {
        return this.tcpFlags.cwr;
    }

    public boolean hasFlagRST() {
        return this.tcpFlags.rst;
    }

    public void setTcpFlags(TCPFlags flags){
        this.tcpFlags = flags;
    }

    public TCPFlags getTcpFlags() {
        return tcpFlags;
    }

    public int getTCPWindow() {
        return TCPWindow;
    }

    public void setTCPWindow(int TCPWindow) {
        this.TCPWindow = TCPWindow;
    }

    public void setSrcMac(byte[] mac){
        this.srcMac = mac;
    }

    public byte[] getSrcMac(){
        return this.srcMac;
    }

    public void setDstMac(byte[] mac){
        this.dstMac = mac;
    }

    public byte[] getDstMac(){
        return this.dstMac;
    }
}
