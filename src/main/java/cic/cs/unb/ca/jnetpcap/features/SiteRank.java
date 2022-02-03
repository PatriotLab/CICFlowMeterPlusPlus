package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;
import org.jnetpcap.protocol.tcpip.Http;

/**
 * Feature that returns the URL of HTTP Request Packets.
 *
 * @author Michael Fahnlander
 */

public class SiteRank extends FeatureCollection {

    private String url = null;

    public SiteRank() {
        new FeatureCollection.FieldBuilder()
                .addField(() -> url, "Site Request")
                //.addField(() -> SSl, "Site Request")
                .build(this);
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        if (url == null) {
            url = String.valueOf(Http.Request.RequestUrl);
        }
    }
}