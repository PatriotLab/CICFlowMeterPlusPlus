package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

public class TimeToLive extends FeatureCollection {
    private final StatsFeature packetTTLstats = new StatsFeature();

    public TimeToLive() {
        new FeatureCollection.FieldBuilder()
                .addField(packetTTLstats, "TTL {0}")
                .build(this);
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        packetTTLstats.addValue(packet.ttl);
    }
}
