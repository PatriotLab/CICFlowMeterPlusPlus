package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

/**
 * Feature that collects flow timestamp and duration
 *
 * @author INSERTNAME
 */

public class Time extends  FeatureCollection {
    boolean seen_first = false;
    public long first_time = 0;
    public long last_time = 0;

    Time(){
        new FeatureCollection.FieldBuilder()
                .addField(this::getStartTime, "Timestamp")
                .addField(this::getDuration, "Duration")
                .build(this);
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        if(!seen_first){
            seen_first = true;
            first_time = packet.getTimeStamp();
        }

        last_time = packet.getTimeStamp();
    }

    public long getStartTime(){
        return first_time;
    }

    public long getDuration() {
        return last_time - first_time;
    }
}
