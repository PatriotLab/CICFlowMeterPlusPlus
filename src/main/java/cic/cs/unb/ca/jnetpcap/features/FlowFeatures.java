package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

public class FlowFeatures extends FeatureCollection {
    public PacketCount packet_count = new PacketCount();
    public FwdBwdSplit<PayloadSize> payload_size;
    public Time times = new Time();

    public String origin;

    private void init() {
        // Initialize any of the members that need special code
        try {
            payload_size = new FwdBwdSplit<>(PayloadSize.class);
        } catch (InstantiationException | IllegalAccessException e) {
            // This will never happen, idk how best to write that
        }
    }

    public FlowFeatures() {
        init();
        fields = new FeatureCollection.FieldBuilder()
                .addField(packet_count)
                .addField(payload_size)
                .addField(times)
                .build();
    }

    public FlowFeatures(BasicPacketInfo packet, long activityTimeout) {
        init();

        fields = new FeatureCollection.FieldBuilder()
                .addField(packet_count)
                .addField(payload_size)
                .addField(times)
                .build();

        origin = packet.fwdFlowId();

        onPacket(packet);
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        packet.isBwdPacket = !origin.equals(packet.fwdFlowId());

        packet_count.onPacket(packet);
        payload_size.onPacket(packet);
        times.onPacket(packet);
    }
}
