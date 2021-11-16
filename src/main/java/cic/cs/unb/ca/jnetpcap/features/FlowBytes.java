package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

public class FlowBytes extends FeatureCollection{
    private long totalBytes = 0;
    private long flowLastTS = 0;
    private long flowStartTS = 0;

    public FlowBytes() {
        new FeatureCollection.FieldBuilder()
                .addField(() -> (double)totalBytes/((double)(flowLastTS-flowStartTS)/1000000L), "Flow Bytes/s")
                .build(this);
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        totalBytes += packet.getPayloadBytes();
        if(flowStartTS == 0){
            flowStartTS = packet.getTimeStamp();
            flowLastTS = packet.getTimeStamp();
        }
        flowLastTS = packet.getTimeStamp();
    }
}
