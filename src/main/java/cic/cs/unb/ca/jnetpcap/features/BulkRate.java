package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

public class BulkRate extends FeatureCollection {
    private long currTime = 0;
    private long tmpSize = 0;

    private long bwdBulkLastTS = 0;
    private long bwdBulkSizeTotal = 0;
    private long bwdBulkStateCount = 0;
    private long bwdBulkDuration = 0;
    private long bwdBulkPacketCount = 0;
    private long bwdBulkStartHelper = 0;
    private long bwdBulkPacketCountHelper = 0;
    private long bwdBulkSizeHelper = 0;

    private long fwdBulkLastTS = 0;
    private long fwdBulkSizeTotal = 0;
    private long fwdBulkStateCount = 0;
    private long fwdBulkDuration = 0;
    private long fwdBulkPacketCount = 0;
    private long fwdBulkStartHelper = 0;
    private long fwdBulkPacketCountHelper = 0;
    private long fwdBulkSizeHelper = 0;

    public BulkRate() {
        new FeatureCollection.FieldBuilder()
                .addField(() -> fwdBulkStateCount == 0 ? 0 : fwdBulkSizeTotal / fwdBulkStateCount, "Fwd Avg Bytes/Bulk")
                .addField(() -> fwdBulkStateCount == 0 ? 0 : fwdBulkPacketCount / fwdBulkStateCount, "Fwd Avg Packets/Bulk")
                .addField(() -> fwdBulkDuration == 0 ? 0 : fwdBulkSizeTotal / (fwdBulkDuration / (double)1000000), "Fwd Bulk Rate")
                .addField(() -> bwdBulkStateCount == 0 ? 0 : bwdBulkSizeTotal / bwdBulkStateCount, "Bwd Avg Bytes/Bulk")
                .addField(() -> bwdBulkStateCount == 0 ? 0 : bwdBulkPacketCount / bwdBulkStateCount, "Bwd Avg Packets/Bulk")
                .addField(() -> bwdBulkDuration == 0 ? 0 : bwdBulkSizeTotal / (bwdBulkDuration / (double)1000000),"Bwd Bulk Rate")
                .build(this);
    }

    private void updateFwdBulk(BasicPacketInfo packet){
        if(bwdBulkLastTS > fwdBulkStartHelper){
            fwdBulkStartHelper = 0;
        }
        if(tmpSize <= 0) {
            return;
        }

        packet.getPayloadPacket();

        if(fwdBulkStartHelper == 0){
            fwdBulkStartHelper = currTime;
            fwdBulkPacketCountHelper = 1;
            fwdBulkSizeHelper = tmpSize;
            fwdBulkLastTS = currTime;
        }
        else{
            if (((currTime - fwdBulkLastTS)/(double)1000000) > 1.0){
                fwdBulkStartHelper = currTime;
                fwdBulkLastTS = currTime;
                fwdBulkPacketCountHelper = 1;
                fwdBulkSizeHelper = tmpSize;
            }
            else{
                fwdBulkPacketCountHelper += 1;
                fwdBulkSizeHelper += tmpSize;
                if(fwdBulkPacketCountHelper == 4){
                    fwdBulkStateCount += 1;
                    fwdBulkPacketCount += fwdBulkPacketCountHelper;
                    fwdBulkSizeTotal += fwdBulkSizeHelper;
                    fwdBulkDuration += currTime - fwdBulkStartHelper;
                }
                else if(fwdBulkPacketCountHelper > 4){
                    fwdBulkPacketCount += 1;
                    fwdBulkSizeTotal += tmpSize;
                    fwdBulkDuration += currTime - fwdBulkLastTS;
                }
                fwdBulkLastTS = currTime;
            }
        }
    }

    private void updateBwdBulk(BasicPacketInfo packet){
        if(fwdBulkLastTS > bwdBulkStartHelper){
            bwdBulkStartHelper = 0;
        }
        if(tmpSize <= 0) {
            return;
        }

        packet.getPayloadPacket();

        if(bwdBulkStartHelper == 0){
            bwdBulkStartHelper = currTime;
            bwdBulkPacketCountHelper = 1;
            bwdBulkSizeHelper = tmpSize;
            bwdBulkLastTS = currTime;
        }
        else{
            if (((currTime - bwdBulkLastTS)/(double)1000000) > 1.0){
                bwdBulkStartHelper = currTime;
                bwdBulkLastTS = currTime;
                bwdBulkPacketCountHelper = 1;
                bwdBulkSizeHelper = tmpSize;
            }
            else{
                bwdBulkPacketCountHelper += 1;
                bwdBulkSizeHelper += tmpSize;
                if(bwdBulkPacketCountHelper == 4){
                    bwdBulkStateCount += 1;
                    bwdBulkPacketCount += bwdBulkPacketCountHelper;
                    bwdBulkSizeTotal += bwdBulkSizeHelper;
                    bwdBulkDuration += currTime - bwdBulkStartHelper;
                }
                else if(bwdBulkPacketCountHelper > 4){
                    bwdBulkPacketCount += 1;
                    bwdBulkSizeTotal += tmpSize;
                    bwdBulkDuration += currTime - bwdBulkLastTS;
                }
                bwdBulkLastTS = currTime;
            }
        }
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        currTime = packet.getTimeStamp();
        tmpSize = packet.getPayloadBytes();
        if(packet.isBwdPacket){
            updateBwdBulk(packet);
        }
        else{
            updateFwdBulk(packet);
        }
    }
}
