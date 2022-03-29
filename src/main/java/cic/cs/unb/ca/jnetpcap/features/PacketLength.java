package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

/**
 * Feature to keep statistics on packet payload sizes in bytes.
 */
public class PacketLength extends FeatureCollection{
    private final StatsFeature payloadSize = new StatsFeature();
    private final StatsFeature headerSize = new StatsFeature();

    public PacketLength(){
        new FeatureCollection.FieldBuilder()
                .addField(payloadSize, "Packet Length {0}")
                .addField(headerSize, "Header Length {0}")
                .build(this);
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        payloadSize.addValue((double) packet.getPayloadBytes());
        headerSize.addValue((double) packet.getHeaderBytes());
    }
}
