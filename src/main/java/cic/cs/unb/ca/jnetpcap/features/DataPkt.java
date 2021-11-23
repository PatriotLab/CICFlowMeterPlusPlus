package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

/**
 * Feature that two values based on the data in the packet.
 * Segment = header bytes
 * Data packet = payload bytes
 *
 * Returns
 *      - actDataPck, or number of fwd packets with data in them (>=1)
 *      - minFwdSeg, or minimum fwd segment size
 *
 * @author Dylan Westlund
 */

public class DataPkt extends FeatureCollection{
    private int actDataPkt = 0;
    private long minFwdSeg;
    private long currentPckSeg;
    private boolean isFirstPacket = true;

    public DataPkt() {
        new FeatureCollection.FieldBuilder()
                .addField(() -> actDataPkt, "Fwd Act Data Pkts")
                .addField(() -> minFwdSeg, "Fwd Header Size Min")
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
        // store the min value
        minFwdSeg = Math.min(minFwdSeg, currentPckSeg);

        isFirstPacket = false;
    }
}