package cic.cs.unb.ca.jnetpcap.features;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class Entropy extends FeatureCollection{
    private int size = 0;
    private HashMap<Float, Integer> values = new HashMap();

    public Entropy() {
        new FeatureCollection.FieldBuilder()
                .addField(() -> calculateEntropy(size), "Entropy")
                .build(this);
    }
    public void add(float value){
        Integer number = values.get(value);
        if(number == null || number == 0){
            values.put(value, 1);
        }
        else if(number >= 1){
            values.put(value, number+1);
        }
        size++;
    }

    private double calculateEntropy(int size){
        if(size == 0){
            return 0;
        }

        double entropy = 0.0;
        Iterator valIterator = values.entrySet().iterator();

        while(valIterator.hasNext()){
            Map.Entry<Float, Integer> new_Map = (Map.Entry<Float,Integer>) valIterator.next();
            double p = 1.0 * new_Map.getValue() / size;
            if(new_Map.getValue() > 0){
                entropy -= p * Math.log(p) / Math.log(2);
            }
        }
        return entropy;

    }
}
