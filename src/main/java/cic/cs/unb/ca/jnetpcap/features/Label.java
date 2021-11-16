
package cic.cs.unb.ca.jnetpcap.features;

public class Label extends  FeatureCollection {
    Label(){
        new FeatureCollection.FieldBuilder()
                .addField(() -> "NeedsManualLabel", "Label")
                .build(this);
    }
}
