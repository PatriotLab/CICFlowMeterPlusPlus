package cic.cs.unb.ca.jnetpcap.features;

import java.util.ArrayList;
import java.util.Collections;

public class Quartile extends FeatureCollection{
    private ArrayList<Float> values = new ArrayList<>();
    private int size = 0;

    public Quartile() {
        new FeatureCollection.FieldBuilder()
                .addField(() -> getFirst(size), "Q1")
                .addField(() -> getSecond(size), "Q2")
                .addField(() -> getThird(size), "Q3")
                .build(this);

    }

    public void add(float value) {
        values.add(value);
        size++;
    }

    private float getFirst(int size){
        if(size < 3){
            return -1;
        }
        Collections.sort(values);
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

    private float getSecond(int size){
        if(size == 0){
            return -1;
        }
        Collections.sort(values);
        if(size % 2 != 0){
            // odd size, pick middle
            return values.get(size/2);
        }
        else{
            // even size, get average of two middle
            return (values.get(size/2) + values.get((size/2)-1))/2;
        }
    }

    private float getThird(int size){
        if(size < 3){
            return -1;
        }
        Collections.sort(values);
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
