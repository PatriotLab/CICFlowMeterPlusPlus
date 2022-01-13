package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

/**
 * Feature to keep statistics on packet payload sizes in bytes.
 */
public class PacketLength extends FeatureCollection{
    private final StatsFeature payloadSize = new StatsFeature();
    private final StatsFeature fwdPayloadSize = new StatsFeature();
    private final StatsFeature bwdPayloadSize = new StatsFeature();

    public PacketLength(){
        new FeatureCollection.FieldBuilder()
                .addField(payloadSize, "Packet Length {0}")
                .addField(() -> fwdPayloadSize.getVariance(), "Fwd Packet Length Variance")
                .addField(() -> bwdPayloadSize.getVariance(), "Bwd Packet Length Variance")
                .build(this);
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {

        payloadSize.addValue((double) packet.getPayloadBytes());
        if(packet.isBwdPacket){
            bwdPayloadSize.addValue(packet.getPayloadBytes());
        }
        else{
            fwdPayloadSize.addValue(packet.getPayloadBytes());
        }
    }
}
