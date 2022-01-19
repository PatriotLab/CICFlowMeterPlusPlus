package cic.cs.unb.ca.jnetpcap.features;
import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;
import org.apache.commons.math3.stat.descriptive.SummaryStatistics;
import org.jnetpcap.newstuff.TestHttp2;
import org.jnetpcap.protocol.tcpip.Http;

import java.util.IntSummaryStatistics;

/**
 * Features that calculate HTTP packet Metadata.
 *
 * @author Michael Fahnlader
 */

public class HttpBytes extends  FeatureCollection{
    //SummaryStatistics summary = new SummaryStatistics();
    public StatsFeature httpSummary = new StatsFeature();

    Http httpData = new Http();
    public HttpBytes() {
        new FeatureCollection.FieldBuilder()
                .addField(() -> httpData.getHeaderLength(), "HTTP Header Bytes")
                .addField(() -> httpData.getHeaderLength(), "HTTP Payload Bytes")
                .addField(() -> httpData.getHeaderLength(), "HTTP Total Bytes")

                .addField(() -> httpData.getHeaderLength(), "HTTP Bytes Avg")
                .addField(() -> httpData.getHeaderLength(), "HTTP Bytes Entropy")
                .addField(() -> httpData.getHeaderLength(), "HTTP Bytes FirstQ")
                .addField(() -> httpData.getHeaderLength(), "HTTP Bytes Max")
                .addField(() -> httpData.getHeaderLength(), "HTTP Bytes Median")
                .addField(() -> httpData.getHeaderLength(), "HTTP Bytes Min")
                .addField(() -> httpData.getHeaderLength(), "HTTP Bytes STDev")
                .addField(() -> httpData.getHeaderLength(), "HTTP Bytes Sum")
                .addField(() -> httpData.getHeaderLength(), "HTTP Bytes ThirdQ")
                .addField(() -> httpData.getHeaderLength(), "HTTP Bytes Variance")
                .build(this);
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        httpSummary.addValue((double) httpData.getHeaderLength());
        httpSummary.addValue((double) httpData.getPayloadLength());
        httpSummary.addValue((double) httpData.getPayloadLength() + httpData.getHeaderLength());
    }
}
