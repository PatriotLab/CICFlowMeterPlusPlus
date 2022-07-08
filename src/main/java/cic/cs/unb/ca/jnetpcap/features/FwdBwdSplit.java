package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

import java.util.function.Supplier;

/**
 * Wrap another feature collection and split traffic between three copies of it, one for all traffic, one for forward
 * traffic, and one for backward traffic.
 * @param <T> {@link FeatureCollection} to wrap and split traffic between
 */
public class FwdBwdSplit<T extends FeatureCollection> extends FeatureCollection {
    public final T total;
    public final T forward;
    public final T backward;

    /**
     * @param constructor A unary function to construct an instance of the class
     */
    public FwdBwdSplit(Supplier<T> constructor) {
        total = constructor.get();
        forward = constructor.get();
        backward = constructor.get();
        new FeatureCollection.FieldBuilder()
                .addField(total)
                .addField(forward, "Fwd {0}")
                .addField(backward, "Bwd {0}")
                .build(this);
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        if(packet.isFwdPacket()){
            forward.onPacket(packet);
        } else {
            backward.onPacket(packet);
        }
        total.onPacket(packet);
    }
}
