package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;
import org.jnetpcap.protocol.tcpip.Http;

import java.net.URL;

/**
 * Feature that returns the URL of HTTP Request Packets.
 *
 * @author Michael Fahnlander
 */

public class SiteRank extends FeatureCollection {

    private String url;

    public SiteRank() {
        new FeatureCollection.FieldBuilder()
                .addField(() -> url, "HTTP Site Request")
                //.addField(() -> SSl, "HTTPS Site Request")
                .build(this);
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        if (url == null) {
            //prints out numbers (length of the Header).
             url = packet.getRequestURL();
        }
    }
}