package cic.cs.unb.ca.jnetpcap.features;

public class MachineLearn extends FeatureCollection{
    String label;
    Double accuracy;
    FlowFeatures flow;

    public MachineLearn(){
        new FeatureCollection.FieldBuilder()
                .addField(() -> label, "Label")
                //.addField(() -> accuracy, "Accuracy")
                .addField(flow)
                .build(this);
    }
}
