package cic.cs.unb.ca.jnetpcap.features;
import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

import java.util.ArrayList;

/**
 * Features that calculate HTTP inter packet arrival time and HTTP Client/Server Inter-Packet Arrival Time.
 *
 * @author Michael Fahnlader
 */

public class HttpIAT extends  FeatureCollection{
    private final StatsFeature httpServerIAT = new StatsFeature();
    private boolean seen_first = false;
    private long last_seen_timestamp = 0;
    private final ArrayList<Long> RequestQueue = new ArrayList<>();
    private final ArrayList<Long> ResponseQueue = new ArrayList<>();
    private final StatsFeature httpIAT = new StatsFeature();

    public HttpIAT() {
        new FieldBuilder()
                .addField(httpIAT, "HTTP IAT {0}")
                .addField(httpServerIAT, "HTTP Server IAT {0}")
                .build(this);
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {

        if(packet.isHTTP) {
            //IAT between HTTP Packets.
            long this_time = packet.getTimeStamp();
            if (!seen_first) {
                seen_first = true;
            } else {
                httpIAT.addValue((double) (this_time - last_seen_timestamp));
            }
            last_seen_timestamp = this_time;

            //IAT between a client's HTTP Request and the HTTP Server's Response.
            if(packet.httpRequestHeader != 0) {
                RequestQueue.add(packet.request_timestamp);
            }
            //Only want extra response packets if there were more than one unanswered request in a row.
            else if(packet.httpResponseHeader != 0 && RequestQueue.toArray().length > ResponseQueue.toArray().length){
                ResponseQueue.add(packet.response_timestamp);
            }

            if(RequestQueue.toArray().length != 0 && ResponseQueue.toArray().length != 0){
                httpServerIAT.addValue((double) (ResponseQueue.get(0) - RequestQueue.get(0)));
                ResponseQueue.remove(0);
                RequestQueue.remove(0);
            }
        }
    }
}
