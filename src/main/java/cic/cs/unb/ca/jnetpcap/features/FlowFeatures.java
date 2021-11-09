package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

public class FlowFeatures extends FeatureCollection {
    public String origin;
    public Time times = new Time();
    public Protocol protocol = new Protocol();
    public FwdBwdSplit<PacketCount> packet_count = new FwdBwdSplit<>(PacketCount::new);
    public FwdBwdSplit<PacketLength> packet_length = new FwdBwdSplit<>(PacketLength::new);
    public DestinationInfo dest_info = new DestinationInfo();
    public SourceInfo src_info = new SourceInfo();
    public TCPFlags tcp_flags = new TCPFlags();
    public FwdBwdSplit<FlowIAT> flow_iat = new FwdBwdSplit<>(FlowIAT::new);
    public ActivityIdle activeIdle;
    public WinBytes initWinBytes = new WinBytes();
    public DataPkt data = new DataPkt();
    public Segment seg = new Segment();

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
                .build(this);
    }

    public FlowFeatures() {
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
