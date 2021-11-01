package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

public class PacketCount extends FeatureCollection {
    public int count = 0;

    PacketCount(){
        new FeatureCollection.FieldBuilder()
                .addField(() -> count, "Packet Count")
                .build(this);
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        count++;
    }
}
