package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class MachineLearn extends FeatureCollection{
    private String label;
    private double accuracy;
    public MachineLearn(){
        new FeatureCollection.FieldBuilder()
                .addField(() -> label, "Label")
                .addField(() -> accuracy, "Accuracy")
                .build(this);
    }

    @Override
    public void onPacket(BasicPacketInfo packet) {
        //Install Machine Learning Python Packages and dependencies
        try {
            Process process = Runtime.getRuntime().exec("pip install -U scikit-learn && pip install sklearn-pandas && pip install sklearn2pmml");
            BufferedReader input = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String output = null;

            while ((output = input.readLine()) != null) {
                System.out.println(output);
            }
        } catch (Exception e) {
            //assert false;//intelij said the next line would throw null pointer '\_/(O_O)\_/'
            System.out.println(e.toString());
            e.printStackTrace();
        }
        //Get Finished CSV

        //Make Label Column and Accuracy column?


        //Run model on CSV

    }
}
