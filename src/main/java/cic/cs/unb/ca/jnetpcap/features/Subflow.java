package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

/**
 * Feature that collects information on subflows in the flow
 * Subflow = bytes/subflow count
 *
 * Returns four values
 *      - Fwd Bytes Subflow - average fwd bytes per subflow
 *      - Fwd Packets Subflow - average fwd packets per subflow
 *      - Bwd Bytes Subflow - average bwd bytes per subflow
 *      - Bwd Packets Subflow - average bwd packets per subflow
 *
 * @author Dylan Westlund
 */

public class Subflow extends FeatureCollection{
    private long fwdBytes = 0;
    private long bwdBytes = 0;
    private long fwdPacket = 0;
    private long bwdPacket = 0;
    private long subflowCount = 0;
    private long subflowLastTS = -1;

    public Subflow() {
        new FeatureCollection.FieldBuilder()
                .addField(() -> subflowCount<=0 ? 0 : fwdBytes/subflowCount, "Fwd Bytes Subflow")
                .addField(() -> subflowCount<=0 ? 0 : fwdPacket/subflowCount, "Fwd Packets Subflow")
                .addField(() -> subflowCount<=0 ? 0 : bwdBytes/subflowCount, "Bwd Bytes Subflow")
                .addField(() -> subflowCount<=0 ? 0 : bwdPacket/subflowCount, "Bwd Packets Subflow")
                .build(this);
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        if(subflowLastTS == -1){
            subflowLastTS = packet.getTimeStamp();
        }
        if(((packet.getTimeStamp() - subflowLastTS)/(double)1000000) > 1.0){
            subflowCount += 1;
        }
        subflowLastTS = packet.getTimeStamp();

        if(packet.isBwdPacket){
            bwdBytes += packet.getPayloadBytes();
            bwdPacket += 1;
        }
        else{
            fwdBytes += packet.getPayloadBytes();
            fwdPacket += 1;
        }
    }
}