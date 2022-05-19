package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

/**
 * Feature that collects protocol for each flow
 *
 * @author Julia Scheaffer
 */

public class Protocol extends FeatureCollection {
    int protocol = 0;

    @Override
    public void onPacket(BasicPacketInfo packet) {
        protocol = packet.getProtocol();
    }

    public Protocol() {
        new FeatureCollection.FieldBuilder()
                .addField(() -> protocol, "Protocol")
                .build(this);
    }
}
