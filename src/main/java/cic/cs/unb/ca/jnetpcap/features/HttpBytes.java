package cic.cs.unb.ca.jnetpcap.features;
import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

/**
 * Features that calculate HTTP packet size and inter packet arrival time.
 *
 * @author Michael Fahnlader
 */

public class HttpBytes extends  FeatureCollection{
    private final StatsFeature httpRequestPayloadStats = new StatsFeature();
    private final StatsFeature httpRequestHeaderStats = new StatsFeature();
    private final StatsFeature httpResponsePayloadStats = new StatsFeature();
    private final StatsFeature httpResponseHeaderStats = new StatsFeature();
    private final StatsFeature httpServerIAT = new StatsFeature();
    private boolean seen_first = false;
    private long last_seen_timestamp = 0;
    private long request = 0;
    private long response = 0;
    private final StatsFeature httpIAT = new StatsFeature();

    public HttpBytes() {
        new FeatureCollection.FieldBuilder()
                .addField(httpRequestHeaderStats, "HTTP Request Header {0}")
                .addField(httpRequestPayloadStats, "HTTP Request Payload {0}")
                .addField(httpResponseHeaderStats, "HTTP Response Header {0}")
                .addField(httpResponsePayloadStats, "HTTP Response Payload {0}")
                //.addField(httpIAT, "HTTP IAT {0}")
                //.addField(httpServerIAT, "HTTP Server IAT {0}")
                .build(this);
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {

        if(packet.isHTTP) {
            //HTTP Packet Size
            httpRequestHeaderStats.addValue(packet.httpRequestHeader);
            httpRequestPayloadStats.addValue(packet.httpRequestPayload);
            httpResponseHeaderStats.addValue(packet.httpResponseHeader);
            httpResponsePayloadStats.addValue(packet.httpResponsePayload);

            /*//IAT between HTTP Packets
            long this_time = packet.getTimeStamp();
            if (!seen_first) {
                seen_first = true;
            } else {
                httpIAT.addValue((double) (this_time - last_seen_timestamp));
            }
            last_seen_timestamp = this_time;

            //IAT between a client's HTTP Request and the HTTP Server's Response
            request = packet.request_timestamp;
            response = packet.response_timestamp;
            if(request != 0 && response != 0) {
                httpServerIAT.addValue((double) (response - request));
            }*/
        }
    }
}
