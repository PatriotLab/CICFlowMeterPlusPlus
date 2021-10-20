package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

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
     * @param containedClass FeatureCollection class to split traffic between
     * @throws InstantiationException if the {@code containedClass} does not have a nullary constructor
     * @throws IllegalAccessException if the {@code containedClass} is not constructable for some other reason
     */
    public FwdBwdSplit(Class<T> containedClass) throws InstantiationException, IllegalAccessException {
        total = containedClass.newInstance();
        forward = containedClass.newInstance();
        backward = containedClass.newInstance();
        fields = new FeatureCollection.FieldBuilder()
                .addField(total)
                .addField(forward, "Fwd {0}")
                .addField(backward, "Bwd {0}")
                .build();
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        if(packet.isForwardPacket()){
            forward.onPacket(packet);
        } else {
            backward.onPacket(packet);
        }
        total.onPacket(packet);
    }
}
