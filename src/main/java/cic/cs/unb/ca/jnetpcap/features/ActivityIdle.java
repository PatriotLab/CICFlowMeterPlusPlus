package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

/**
 * Feature that collects amount of time a flow is active vs idling.
 * Returns active and idle timing statistics per flow
 *
 * @author Dylan Westlund
 */

public class ActivityIdle extends FeatureCollection{
    private final long timeout;
    private long currentTime;
    private long lastPacketTS = -1L;
    private long startActiveTS;
    private long endActiveTS;
    private final StatsFeature activeSummary = new StatsFeature();
    private final StatsFeature idleSummary = new StatsFeature();


    public ActivityIdle(long activityTimeout) {
        timeout = activityTimeout;

        new FeatureCollection.FieldBuilder()
                .addField(activeSummary, "Active {0}")
                .addField(idleSummary, "Idle {0}")
                .build(this);
    }

    private void updateActiveIdleTS(){
        // update endActiveTS and startActiveTS
        if((currentTime - lastPacketTS) > timeout){
            // packet could be idling
            if(endActiveTS - startActiveTS > 0){
                // packet is active
                activeSummary.addValue((double)(endActiveTS - startActiveTS));
            }
            // packet is idling
            idleSummary.addValue((double)(currentTime - endActiveTS));
            endActiveTS = currentTime;
            startActiveTS = currentTime;
        }
        else{
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
