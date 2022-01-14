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
                .addField(() -> httpSummary, "HTTP Header Bytes")
                .addField(() -> httpSummary, "HTTP Payload Bytes")
                .addField(() -> httpSummary, "HTTP Total Bytes")

                /*.addField(() -> , "HTTP Bytes Avg")
                .addField(() -> httpData.getHeaderLength(), "HTTP Bytes Entropy")
                .addField(() -> , "HTTP Bytes FirstQ")
                .addField(() -> , "HTTP Bytes Max")
                .addField(() -> , "HTTP Bytes Median")
                .addField(() -> , "HTTP Bytes Min")
                .addField(() -> , "HTTP Bytes STDev")
                .addField(() -> , "HTTP Bytes Sum")
                .addField(() -> , "HTTP Bytes ThirdQ")
                .addField(() -> , "HTTP Bytes Variance")*/
                .build(this);
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        httpSummary.addValue((double) httpData.getHeaderLength());
        httpSummary.addValue((double) httpData.getPayloadLength());
        httpSummary.addValue((double) httpData.getPayloadLength() + httpData.getHeaderLength());
    }
}
