package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

public class Segment extends FeatureCollection{
    private boolean isBackward;
    private StatsFeature fwdPckBytes = new StatsFeature();
    private StatsFeature bwdPckBytes = new StatsFeature();

    public Segment() {
        new FeatureCollection.FieldBuilder()
                .addField(fwdPckBytes, "Fwd Segment Size {0}")
                .addField(bwdPckBytes, "Bwd Segment Size {0}")
                .build(this);
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        isBackward = packet.isBwdPacket;
        if(isBackward){
            // Backward packet
            bwdPckBytes.addValue(packet.getPayloadBytes());

        }
        else{
            // Forward packet
            fwdPckBytes.addValue(packet.getPayloadBytes());
        }
    }
}
