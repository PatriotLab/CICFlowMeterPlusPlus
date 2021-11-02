package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

public class DataPkt extends FeatureCollection{
    private int actDataPkt = 0;
    private boolean isFirstPacket = true;

    public DataPkt() {
        new FeatureCollection.FieldBuilder()
                .addField(() -> actDataPkt, "Fwd Act Data Pkts")
                .build(this);
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        if(!packet.isBwdPacket && !isFirstPacket){
            if(packet.getPayloadBytes() >= 1){
                actDataPkt++;
            }
        }
        isFirstPacket = false;
    }
}