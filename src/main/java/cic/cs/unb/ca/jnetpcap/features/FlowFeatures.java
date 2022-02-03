package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

import java.util.Arrays;
import java.util.LinkedHashMap;

public class FlowFeatures extends FeatureCollection {
    public String origin;
    public Time times = new Time();
    public Protocol protocol = new Protocol();
    public FwdBwdSplit<PacketCount> packet_count = new FwdBwdSplit<>(PacketCount::new);
    public FwdBwdSplit<PacketLength> packet_length = new FwdBwdSplit<>(PacketLength::new);
    public DestinationInfo dest_info = new DestinationInfo();
    public SourceInfo src_info = new SourceInfo();
    public FwdBwdSplit<TCPFlags> tcp_flags = new FwdBwdSplit<>(TCPFlags::new);
    public FwdBwdSplit<FlowIAT> flow_iat = new FwdBwdSplit<>(FlowIAT::new);
    public ActivityIdle activeIdle;
    public WinBytes initWinBytes = new WinBytes();
    public DataPkt data = new DataPkt();
    public Segment seg = new Segment();
    public Subflow subflow = new Subflow();
    public FlowBytes flowbytes = new FlowBytes();
    public FwdBwdSplit<TimeToLive> ttl = new FwdBwdSplit<>(TimeToLive::new);
    public Label label = new Label();
    public SiteRank siteRank = new  SiteRank();

    public static String[] getHeaders() {
        return new FlowFeatures().getHeader();
    }

    private static final LinkedHashMap<String, String> compatMap = new LinkedHashMap<>();

    static {
        // Add all the entries to the compat map
        compatMap.put("Flow ID", "Origin");
        compatMap.put("Src IP", "Source IP Address");
        compatMap.put("Src Port", "Source Port");
        compatMap.put("Dst IP", "Destination IP Address");
        compatMap.put("Dst Port", "Destination Port");
        compatMap.put("Protocol", "Protocol");
        compatMap.put("Timestamp", "Timestamp");
        compatMap.put("Flow Duration", "Duration");
        compatMap.put("Total Fwd Packet", "Fwd Packet Count");
        compatMap.put("Total Bwd packets", "Bwd Packet Count"); // this is a crime
        compatMap.put("Total Length of Fwd Packet", "Fwd Packet Length Total");
        compatMap.put("Total Length of Bwd Packet", "Bwd Packet Length Total");
        compatMap.put("Fwd Packet Length Max", "Fwd Packet Length Max");
        compatMap.put("Fwd Packet Length Min", "Fwd Packet Length Min");
        compatMap.put("Fwd Packet Length Mean", "Fwd Packet Length Mean");
        compatMap.put("Fwd Packet Length Std", "Fwd Packet Length Std");
        compatMap.put("Bwd Packet Length Max", "Bwd Packet Length Max");
        compatMap.put("Bwd Packet Length Min", "Bwd Packet Length Min");
        compatMap.put("Bwd Packet Length Mean", "Bwd Packet Length Mean");
        compatMap.put("Bwd Packet Length Std", "Bwd Packet Length Std");
        compatMap.put("Flow Bytes/s", "Flow Bytes/s");
        compatMap.put("Flow Packets/s", null);
        compatMap.put("Flow IAT Mean", "IAT Mean");
        compatMap.put("Flow IAT Std", "IAT Std");
        compatMap.put("Flow IAT Max", "IAT Max");
        compatMap.put("Flow IAT Min", "IAT Min");
        compatMap.put("Fwd IAT Mean", "Fwd IAT Mean");
        compatMap.put("Fwd IAT Std", "Fwd IAT Std");
        compatMap.put("Fwd IAT Max", "Fwd IAT Max");
        compatMap.put("Fwd IAT Min", "Fwd IAT Min");
        compatMap.put("Bwd IAT Mean", "Bwd IAT Mean");
        compatMap.put("Bwd IAT Std", "Bwd IAT Std");
        compatMap.put("Bwd IAT Max", "Bwd IAT Max");
        compatMap.put("Bwd IAT Min", "Bwd IAT Min");
        compatMap.put("Fwd PSH Flags", "Fwd Count PSH Flag");
        compatMap.put("Bwd PSH Flags", "Bwd Count PSH Flag");
        compatMap.put("Fwd URG Flags", "Fwd Count PSH Flag");
        compatMap.put("Bwd URG Flags", "Bwd Count URG Flag");
        compatMap.put("Fwd Header Length", null);
        compatMap.put("Bwd Header Length", null);
        compatMap.put("Fwd Packets/s", null);
        compatMap.put("Bwd Packets/s", null);
        compatMap.put("Packet Length Min", "Packet Length Min");
        compatMap.put("Packet Length Max", "Packet Length Max");
        compatMap.put("Packet Length Mean", "Packet Length Mean");
        compatMap.put("Packet Length Std", "Packet Length Std");
        compatMap.put("Packet Length Variance", null);
        compatMap.put("FIN Flag Count", "Count FIN Flag");
        compatMap.put("SYN Flag Count", "Count SYN Flag");
        compatMap.put("RST Flag Count", "Count RST Flag");
        compatMap.put("PSH Flag Count", "Count PSH Flag");
        compatMap.put("ACK Flag Count", "Count ACK Flag");
        compatMap.put("URG Flag Count", "Count URG Flag");
        compatMap.put("CWR Flag Count", "Count CWR Flag");
        compatMap.put("ECE Flag Count", "Count ECE Flag");
        compatMap.put("Down/Up Ratio", null);
        compatMap.put("Average Packet Size", "Packet Length Mean"); // This is stupid. Yes, packet length mean is just in here twice
        compatMap.put("Fwd Segment Size Avg", "Fwd Segment Size Mean");
        compatMap.put("Bwd Segment Size Avg", "Fwd Segment Size Mean");
        compatMap.put("Fwd Bytes/Bulk Avg", null);
        compatMap.put("Fwd Packet/Bulk Avg", null);
        compatMap.put("Fwd Bulk Rate Avg", null);
        compatMap.put("Bwd Bytes/Bulk Avg", null);
        compatMap.put("Bwd Packet/Bulk Avg", null);
        compatMap.put("Bwd Bulk Rate Avg", null);
        compatMap.put("Subflow Fwd Packets", "Fwd Packets Subflow");
        compatMap.put("Subflow Fwd Bytes", "Fwd Bytes Subflow");
        compatMap.put("Subflow Bwd Packets", "Bwd Packets Subflow");
        compatMap.put("Subflow Bwd Bytes", "Bwd Bytes Subflow");
        compatMap.put("FWD Init Win Bytes", "FWD Init Win Bytes");
        compatMap.put("Bwd Init Win Bytes", "Bwd Init Win Bytes");
        compatMap.put("Fwd Act Data Pkts", "Fwd Act Data Pkts"); // terrible name
        compatMap.put("Fwd Seg Size Min", "Fwd Packet Length Min"); // why does this exist
        compatMap.put("Active Mean", "Active Mean");
        compatMap.put("Active Std", "Active Std");
        compatMap.put("Active Max", "Active Max");
        compatMap.put("Active Min", "Active Min");
        compatMap.put("Idle Mean", "Idle Mean");
        compatMap.put("Idle Std", "Idle Std");
        compatMap.put("Idle Max", "Idle Max");
        compatMap.put("Idle Min", "Idle Min");
        compatMap.put("Label", "Label");
    }

    private static Integer[] getCompatShuffle() {
        String[] currentHeaders = getHeaders();
        return compatMap.values().stream().map(s -> {
            if (s != null) {
                return Arrays.asList(currentHeaders).indexOf(s);
            } else {
                return -1;
            }
        }).toArray(Integer[]::new);
    }

    public static String[] getCompatHeaders() {
        return compatMap.keySet().toArray(new String[]{});
    }

    public String[] getCompatData() {
        String[] currentData = getData();
        return Arrays.stream(getCompatShuffle()).map(i -> {
            if (i == -1) {
                return "";
            } else {
                return currentData[i];
            }
        }).toArray(String[]::new);
    }

    static final boolean enableColumnCompat = true;

    public final String dumpFlowBasedFeaturesEx() {
        if(enableColumnCompat){
            return String.join(",", getCompatData());
        } else {
            return String.join(",", getData());
        }
    }

    public static String dumpHeader() {
        if(enableColumnCompat){
            return String.join(",", getCompatHeaders());
        } else {
            return String.join(",", getHeaders());
        }
    }

    private void init(long activityTimeout) {
        activeIdle = new ActivityIdle(activityTimeout);
        new FeatureCollection.FieldBuilder()
                .addField(() -> origin, "Origin")
                .addField(times)
                .addField(protocol)
                .addField(packet_count)
                .addField(packet_length)
                .addField(tcp_flags)
                .addField(dest_info)
                .addField(src_info)
                .addField(flow_iat)
                .addField(activeIdle)
                .addField(initWinBytes)
                .addField(data)
                .addField(seg)
                .addField(subflow)
                .addField(flowbytes)
                .addField(label)
                .addField(ttl)
                .addField(siteRank)
                .build(this);
    }

    private FlowFeatures() {
        init(0);
    }

    public FlowFeatures(BasicPacketInfo packet, long activityTimeout) {
        init(activityTimeout);

        origin = packet.fwdFlowId();

        onPacket(packet);
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        packet.isBwdPacket = !origin.equals(packet.fwdFlowId());
        this.delegatePacket(packet);
    }
}
