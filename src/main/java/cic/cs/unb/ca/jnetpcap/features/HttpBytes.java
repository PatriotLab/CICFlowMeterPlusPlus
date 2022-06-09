package cic.cs.unb.ca.jnetpcap.features;
import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

/**
 * Features that calculate HTTP packet size.
 *
 * @author Michael Fahnlader
 */

public class HttpBytes extends  FeatureCollection{
    private final StatsFeature httpRequestPayloadStats = new StatsFeature();
    private final StatsFeature httpRequestHeaderStats = new StatsFeature();
    private final StatsFeature httpResponsePayloadStats = new StatsFeature();
    private final StatsFeature httpResponseHeaderStats = new StatsFeature();

    public HttpBytes() {
        new FeatureCollection.FieldBuilder()
                .addField(httpRequestHeaderStats, "HTTP Request Header {0}")
                .addField(httpRequestPayloadStats, "HTTP Request Payload {0}")
                .addField(httpResponseHeaderStats, "HTTP Response Header {0}")
                .addField(httpResponsePayloadStats, "HTTP Response Payload {0}")
                .build(this);
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {

        if(packet.isHTTP) {
            //HTTP Packet Size.
            httpRequestHeaderStats.addValue(packet.httpRequestHeader);
            httpRequestPayloadStats.addValue(packet.httpRequestPayload);
            httpResponseHeaderStats.addValue(packet.httpResponseHeader);
            httpResponsePayloadStats.addValue(packet.httpResponsePayload);
        }
    }
}
