package cic.cs.unb.ca.jnetpcap.features;

import java.util.Arrays;

public class Test {
    public static void main(String[] args) throws InstantiationException, IllegalAccessException {
        System.out.println("Stuff");
        FlowFeatures features = new FlowFeatures();

        System.out.println(Arrays.toString(features.getHeader()));
        System.out.println(Arrays.toString(features.getData()));
    }
}
