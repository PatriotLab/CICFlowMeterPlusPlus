package cic.cs.unb.ca.jnetpcap.features;

import java.util.ArrayList;
import java.util.HashMap;

public class Entropy {
    private ArrayList<Float> values;
    private int size;

    public Entropy(ArrayList<Float> values) {
        this.values = values;
    }

    private float calculateEntropy(){
        long entropy = 0;
        size = values.size();
        HashMap<Float, Integer> freq = new HashMap<>();

        for(int i = 0; i < size; i++){

        }
        return entropy;
    }
}
