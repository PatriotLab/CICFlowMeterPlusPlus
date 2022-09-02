package cic.cs.unb.ca.jnetpcap.features;

public class FlowPrediction extends FeatureCollection{
    String label;
    double accuracy;
    FlowFeatures flow;

    public FlowPrediction(String label, double accuracy, FlowFeatures flow){
        this.label = label;
        this.accuracy = accuracy;
        this.flow = flow;

        new FeatureCollection.FieldBuilder()
            .addField(() -> label, "Label")
            .addField(() -> accuracy, "Accuracy")
            .addField(flow)
            .build(this);
    }
}
