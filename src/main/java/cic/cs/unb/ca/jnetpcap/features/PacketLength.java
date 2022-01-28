package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

/**
 * Feature to keep statistics on packet payload sizes in bytes.
 */
public class PacketLength extends FeatureCollection{
    private final StatsFeature payloadSize = new StatsFeature();
    private final StatsFeature fwdPayloadSize = new StatsFeature();
    private final StatsFeature bwdPayloadSize = new StatsFeature();
    private final Quartile quart = new Quartile();
    private final Quartile fwdQuart = new Quartile();
    private final Quartile bwdQuart = new Quartile();
    private final Entropy ent = new Entropy();

    public PacketLength(){
        new FeatureCollection.FieldBuilder()
                .addField(payloadSize, "Packet Length {0}")
                .addField(quart, "Packet Length {0}")
                .addField(fwdQuart, "Fwd Packet Length {0}") // returns Q1 Q2 Q3
                .addField(bwdQuart, "Bwd Packet Length {0}")
                .addField(ent, "Packet Length {0}")
                .build(this);
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {

        payloadSize.addValue((double) packet.getPayloadBytes());
        if(packet.isBwdPacket){
            bwdPayloadSize.addValue(packet.getPayloadBytes());
            bwdQuart.add(packet.getPayloadBytes());
        }
        else{
            fwdPayloadSize.addValue(packet.getPayloadBytes());
            fwdQuart.add(packet.getPayloadBytes());
        }
        quart.add(packet.getPayloadBytes());
        ent.add(packet.getPayloadBytes());
    }
}
