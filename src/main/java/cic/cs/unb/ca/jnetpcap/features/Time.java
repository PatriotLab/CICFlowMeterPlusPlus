package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

public class Time extends  FeatureCollection {
    boolean seen_first = false;
    public long first_time = 0;
    public long last_time = 0;

    Time(){
        fields = new FeatureCollection.FieldBuilder()
                .addField(() -> first_time, "Timestamp")
                .addField(() -> last_time - first_time, "Duration")
                .build();
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
}
