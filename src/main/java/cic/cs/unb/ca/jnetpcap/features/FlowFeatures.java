package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicFlow;
import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

public class FlowFeatures extends FeatureCollection {
    PacketCount packet_count = new PacketCount();
    FwdBwdSplit<PayloadSize> payload_size = new FwdBwdSplit<>(PayloadSize.class);

    FlowFeatures() throws InstantiationException, IllegalAccessException {
        fields = new FeatureCollection.FieldBuilder()
                .addField(packet_count)
                .addField(payload_size)
                .build();
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        packet_count.onPacket(packet);
        payload_size.onPacket(packet);
    }
}
