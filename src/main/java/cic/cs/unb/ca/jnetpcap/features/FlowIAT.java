package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

public class FlowIAT extends FeatureCollection {
    private boolean seen_first = false;
    private long last_seen_timestamp = 0;
    private StatsFeature iat_summary = new StatsFeature();

    public FlowIAT() {
        fields = new FeatureCollection.FieldBuilder()
                .addField(iat_summary, "IAT {0}")
                .build();
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        long this_time = packet.getTimeStamp();
        if(!seen_first){
            seen_first = true;
        } else {
            iat_summary.addValue((double)(this_time - last_seen_timestamp));
        }
        last_seen_timestamp = this_time;
    }
}