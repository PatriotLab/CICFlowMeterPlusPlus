package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

/**
 * Feature that collects returns the flow payload bytes/s in each flow.
 *
 * @author Dylan Westlund
 */
public class FlowBytes extends FeatureCollection{
    private long totalBytes = 0;
    private long flowLastTS = 0;
    private long flowStartTS = 0;

    public FlowBytes() {
        new FeatureCollection.FieldBuilder()
                .addField(() -> nanCheck(calculateFlowRate()), "Flow Bytes/s")
                .build(this);
    }

    public double calculateFlowRate() {
        return (double)totalBytes/((double)(flowLastTS-flowStartTS)/1000000L);
    }

    // This is a hack to make sure that if there is no data, it will instead return zero
    // Copied from StatsFeature.java
    private static double nanCheck(double val) {
        if(Double.isNaN(val)){
            return 0.0;
        } else {
            return val;
        }
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
