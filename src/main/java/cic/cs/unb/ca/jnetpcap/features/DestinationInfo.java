package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;
import org.jnetpcap.packet.format.FormatUtils;

public class DestinationInfo extends FeatureCollection {
    private int destPort = 0;
    private byte[] dest = null;

    public DestinationInfo() {
        new FeatureCollection.FieldBuilder()
                .addField(() -> FormatUtils.ip(dest), "Destination IP Address")
                .addField(() -> destPort, "Destination Port")
                .build(this);
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        if (dest == null) {
            dest = packet.getDst();
            destPort = packet.getDstPort();
        }
    }
}
