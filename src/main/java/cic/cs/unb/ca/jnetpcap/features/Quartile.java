package cic.cs.unb.ca.jnetpcap.features;

import java.util.ArrayList;
import java.util.Collections;

public class Quartile extends FeatureCollection{
    private ArrayList<Float> values = new ArrayList<>();
    private int size = 0;

    private float Q2 = 0;
    private float Q1 = 0;
    private float Q3 = 0;

    public Quartile() {
        new FeatureCollection.FieldBuilder()
                .addField(() -> Q1, "Q2")
                .addField(() -> Q2, "Q1")
                .addField(() -> Q3, "Q3")
                .build(this);

    }

    public void add(float value) {
        values.add(value);
        Collections.sort(values);
        size = values.size();
        Q2 = getQuartile(0, size, values);
        Q1 = getQuartile(0, Math.round(size / 2), values);
        Q3 = getQuartile(Math.round(size / 2) + 1, size, values);

    }

    private float getQuartile(int low, int high, ArrayList<Float> values){
        if(high == 0){
            return 0;
        }
        if(high == 1){
            return values.get(0);

        }
        if(high == 2){
            return (values.get(0) + values.get(1))/2;
        }
        float quartile = 0;
        int range = high - low;
        float dividend = 0.5f;
        if (low != 0){
            dividend = 0.75f;
        }
        if (range % 2 == 0){
            // even
            float term1 = values.get(Math.round((high*dividend)) - 1);
            float term2 = values.get(Math.round(high*dividend));
            quartile = (term1 + term2) / 2;
        }
        else{
            // odd
            quartile = values.get(Math.round(((high + 1)*dividend)) - 1);
        }

        return quartile;
    }
}
