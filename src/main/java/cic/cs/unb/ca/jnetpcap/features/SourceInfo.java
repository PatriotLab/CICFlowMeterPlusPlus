package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;
import org.jnetpcap.packet.format.FormatUtils;

/**
 * Feature that returns source IP and source port.
 *
 * @author Julia Scheaffer
 */

public class SourceInfo extends FeatureCollection {
    private int srcPort = 0;
    private byte[] src = null;
    private byte[] srcMac = null;
    private int dstPort = 0;
    private byte[] dst = null;
    private byte[] dstMac = null;

    public SourceInfo() {
        new FeatureCollection.FieldBuilder()
                .addField(() -> FormatUtils.ip(src), "Source IP Address")
                .addField(() -> srcPort, "Source Port")
                .addField(() -> FormatUtils.mac(srcMac), "Source MAC Address")
                .addField(() -> FormatUtils.ip(dst), "Destination IP Address")
                .addField(() -> dstPort, "Destination Port")
                .addField(() -> FormatUtils.mac(dstMac), "Destination MAC Address")
                .build(this);
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        if (src == null) {
            src = packet.getSrc();
            srcPort = packet.getSrcPort();
            srcMac = packet.getSrcMac();
            dst = packet.getDst();
            dstPort = packet.getDstPort();
            dstMac = packet.getDstMac();
        }
    }
}
