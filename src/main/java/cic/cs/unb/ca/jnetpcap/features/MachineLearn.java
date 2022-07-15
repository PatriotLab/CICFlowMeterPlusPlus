package cic.cs.unb.ca.jnetpcap.features;

public class MachineLearn extends FeatureCollection{
    String label;
    Double accuracy;

    public MachineLearn(){
        new FeatureCollection.FieldBuilder()
                .addField(() -> label, "Label")
                .addField(() -> accuracy, "Accuracy")
                .build(this);
    }
}
