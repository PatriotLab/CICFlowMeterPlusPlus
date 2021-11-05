package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;
import org.jnetpcap.packet.format.FormatUtils;

public class SourceInfo extends FeatureCollection {
    private int srcPort = 0;
    private byte[] src = null;

    public SourceInfo() {
        new FeatureCollection.FieldBuilder()
                .addField(() -> FormatUtils.ip(src), "Source IP Address")
                .addField(() -> srcPort, "Source Port")
                .build(this);
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        if (src == null) {
            src = packet.getSrc();
            srcPort = packet.getSrcPort();
        }
    }
}
