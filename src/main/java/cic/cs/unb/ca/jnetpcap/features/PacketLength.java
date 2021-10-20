package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

/**
 * Feature to keep statistics on packet payload sizes in bytes.
 */
public class PacketLength extends FeatureCollection{
    private final StatsFeature payloadSize = new StatsFeature();

    public PacketLength(){
        fields = new FeatureCollection.FieldBuilder()
                .addField(payloadSize, "Packet Length {0}")
                .build();
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        payloadSize.addValue((double) packet.getPayloadBytes());
    }
}
