package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

public class PacketCount extends FeatureCollection {
    int packetCount = 0;

    PacketCount(){
        fields = new FeatureCollection.FieldBuilder()
                .addField(() -> packetCount, "Packet Count")
                .build();
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        packetCount++;
    }
}
