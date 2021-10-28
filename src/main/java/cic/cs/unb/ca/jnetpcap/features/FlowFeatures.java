package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

public class FlowFeatures extends FeatureCollection {
    public String origin;
    public Time times = new Time();
    public Protocol protocol = new Protocol();
    public FwdBwdSplit<PacketCount> packet_count;
    public FwdBwdSplit<PacketLength> packet_length;
    public TCPFlags tcp_flags = new TCPFlags();
    public FwdBwdSplit<FlowIAT> flow_iat;
    public ActivityIdle activeIdle;
    public long activityTimeout = 0L;

    private void init() {
        // Initialize any of the members that need special code
        try {
            packet_count = new FwdBwdSplit<>(PacketCount.class);
            packet_length = new FwdBwdSplit<>(PacketLength.class);
            flow_iat = new FwdBwdSplit<>(FlowIAT.class);
            activeIdle = new ActivityIdle(activityTimeout);
        } catch (InstantiationException | IllegalAccessException e) {
            logger.error("FlowFeatures could not be initialized");
        }

        fields = new FeatureCollection.FieldBuilder()
                .addField(() -> origin, "Origin")
                .addField(times)
                .addField(protocol)
                .addField(packet_count)
                .addField(packet_length)
                .addField(tcp_flags)
                .addField(flow_iat)
                .addField(activeIdle)
                .build();
    }

    public FlowFeatures() {
        init();
    }

    public FlowFeatures(BasicPacketInfo packet, long activityTimeout) {
        this.activityTimeout = activityTimeout;
        init();

        origin = packet.fwdFlowId();

        onPacket(packet);
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        packet.isBwdPacket = !origin.equals(packet.fwdFlowId());

        protocol.onPacket(packet);
        packet_count.onPacket(packet);
        packet_length.onPacket(packet);
        times.onPacket(packet);
        tcp_flags.onPacket(packet);
        flow_iat.onPacket(packet);
        activeIdle.onPacket(packet);
    }
}
