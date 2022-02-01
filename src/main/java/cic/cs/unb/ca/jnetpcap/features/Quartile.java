package cic.cs.unb.ca.jnetpcap.features;

import java.util.ArrayList;
import java.util.Collections;

/**
 * Feature class that returns quartiles 1, 2, and 3.
 *
 * @author Dylan Westlund
 */

public class Quartile extends FeatureCollection{
    private ArrayList<Float> values = new ArrayList<>();
    private int size = 0;

    private float Q2 = 0;
    private float Q1 = 0;
    private float Q3 = 0;

    public Quartile() {
        new FeatureCollection.FieldBuilder()
                .addField(() -> Q1, "Q1")
                .addField(() -> Q2, "Q2")
                .addField(() -> Q3, "Q3")
                .build(this);

    }

    public void add(float value) {
        values.add(value);
        Collections.sort(values);
        size = values.size();
        Q2 = getSecond();
        Q1 = getFirst();
        Q3 = getThird();

    }

    private float getFirst(){
        if(size < 3){
            return -1;
        }
        int midpoint = (size / 2);
        if(size % 2 != 0){
            // odd size
            if (midpoint % 2 == 0) {
                // even quarter
                return (values.get(midpoint / 2) + values.get((midpoint / 2) - 1)) / 2;
            } else {
                // odd quarter
                return (values.get(midpoint / 2));
            }
        }
        else{
            //even size
            if(midpoint % 2 == 0){
                // even quarter
                return (values.get(((midpoint-1)/2)+1) + values.get(midpoint))/2;
            }
            else{
                // odd quarter
                return (values.get((midpoint-1)/2));
            }
        }

    }

    private float getSecond(){
        if(size % 2 != 0){
            // odd size, pick middle
            return values.get(size/2);
        }
        else{
            // even size, get average of two middle
            return (values.get(size/2) + values.get((size/2)-1))/2;
        }
    }

    private float getThird(){
        if(size < 3){
            return -1;
        }
        int midpoint = size/2;
        if(size % 2 != 0){
            // odd size
            if(midpoint % 2 != 0){
                // odd quarter
                return (values.get((int) (size * 0.75d)));
            }
            else{
                // even quarter
                return (values.get((int) (size*.75d)) + values.get((int) ((size*.75d)+1)))/2;
            }
        }
        else{
            // even size
            if(midpoint % 2 != 0){
                // odd quarter
                return values.get((int) (size*.75d));
            }
            else{
                // even quarter
                return (values.get((int) (size*.75d)) + values.get((int) ((size*.75d)-1)))/2;
            }
        }

    }
}