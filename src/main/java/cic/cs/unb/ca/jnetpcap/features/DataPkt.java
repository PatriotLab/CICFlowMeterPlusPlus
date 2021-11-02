package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

public class DataPkt extends FeatureCollection{
    private int actDataPkt = 0;
    private long minFwdSeg;
    private long currentPckSeg;
    private boolean isFirstPacket = true;

    public DataPkt() {
        new FeatureCollection.FieldBuilder()
                .addField(() -> actDataPkt, "Fwd Act Data Pkts")
                .addField(() -> minFwdSeg, "Fwd Seg Size Min")
                .build(this);
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        if(!packet.isBwdPacket && !isFirstPacket){
            if(packet.getPayloadBytes() >= 1){
                actDataPkt++;
            }
        }

        if(isFirstPacket){
            minFwdSeg = packet.getHeaderBytes();
        }

        currentPckSeg = packet.getHeaderBytes();
        minFwdSeg = Math.min(minFwdSeg, currentPckSeg);

        isFirstPacket = false;
    }
}