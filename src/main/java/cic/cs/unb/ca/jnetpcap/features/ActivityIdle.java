package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

public class ActivityIdle extends FeatureCollection{
    private long timeout;
    private long currentTime;
    private long lastPacketTS = -1L;
    private long startActiveTS;
    private long endActiveTS;
    private StatsFeature active_summary = new StatsFeature();
    private StatsFeature idle_summary = new StatsFeature();


    public ActivityIdle(long activityTimeout) {
        timeout = activityTimeout;

        fields = new FeatureCollection.FieldBuilder()
                .addField(active_summary, "Active {0}")
                .addField(idle_summary, "Idle {0}")
                .build();
    }

    private void updateActiveIdleTS(){
        // update endActiveTS and startActiveTS
        if((currentTime - lastPacketTS) > timeout){
            // packet was idling
            if(endActiveTS - startActiveTS > 0){
                active_summary.addValue((double)(endActiveTS - startActiveTS));
            }
            idle_summary.addValue((double)(currentTime - endActiveTS));
            endActiveTS = currentTime;
            startActiveTS = currentTime;
        }
        else{
            // packet is active
            endActiveTS = currentTime;
        }

    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        if(lastPacketTS == -1){
            lastPacketTS = packet.getTimeStamp();
            startActiveTS = packet.getTimeStamp();
            endActiveTS = packet.getTimeStamp();
        }
        currentTime = packet.getTimeStamp();
        updateActiveIdleTS();
        lastPacketTS = packet.getTimeStamp();

    }
}
