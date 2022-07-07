package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;
import org.jpmml.evaluator.*;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.List;
import java.util.Map;

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
        // Building a model evaluator from a PMML file
            Evaluator evaluator = new LoadingModelEvaluatorBuilder()
                    .load(new File("model.pmml"))//change this
                    .build();

        // Perforing the self-check
            evaluator.verify();

        // Printing input (x1, x2, .., xn) fields
            List<InputField> inputFields = evaluator.getInputFields();
            System.out.println("Input fields: " + inputFields);

        // Printing primary result (y) field(s)
            List<TargetField> targetFields = evaluator.getTargetFields();
            System.out.println("Target field(s): " + targetFields);

        // Printing secondary result (eg. probability(y), decision(y)) fields
            List<OutputField> outputFields = evaluator.getOutputFields();
            System.out.println("Output fields: " + outputFields);

        // Iterating through columnar data (eg. a CSV file, an SQL result set)
            while(true){
                // Reading a record from the data source
                //is there an existing record that we can point the machine learning at to ingest data?
                Map<String, ?> arguments = 0; //Set arguments equal to a record
                if(arguments == null){
                    break;
                }

                // Evaluating the model
                Map<String, ?> results = evaluator.evaluate(arguments);

                // Decoupling results from the JPMML-Evaluator runtime environment
                results = EvaluatorUtil.decodeAll(results);

                // Writing a record to the data sink
                writeRecord(results);
            }

        // Making the model evaluator eligible for garbage collection
        evaluator = null;
    }

    private Map<String,?> readRecord() {
        //This might be redundant if we can give the model a record of all the pcap data

        return;
    }
    private void writeRecord(Map<String,?> results) {
        //set label and accuracy values here?
    }
}
