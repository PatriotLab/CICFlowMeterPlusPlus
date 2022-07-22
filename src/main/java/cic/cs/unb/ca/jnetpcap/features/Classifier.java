package cic.cs.unb.ca.jnetpcap.features;
import jakarta.xml.bind.JAXBException;
//import org.apache.log4j.MDC;
//import org.dmg.pmml.FieldName;
import org.jpmml.evaluator.*;
import org.sparkproject.dmg.pmml.FieldName;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.*;

public class Classifier {
    final private Evaluator evaluator;
    private InputField .;

    public Classifier(String modelPath) throws JAXBException, IOException, ParserConfigurationException, SAXException {
        File model_file = new File(modelPath);

        evaluator = new LoadingModelEvaluatorBuilder()
                .load(model_file)
                .build();
        evaluator.verify();
    }

    public void predict(FlowFeatures rowData) {

        FieldName targetName = FieldName.create(evaluator.getTargetFields().get(0).getName());
        FieldValue inputValue;

        Map<String, Double> userArguments = rowData.getHeader();
        Map<String, FieldValue> arguments = new LinkedHashMap<>();
        List<InputField> inputFields = evaluator.getInputFields();

        //Iterate through, adding the column entries into the arguments
        //Hang on, we don't need column names, do we?

        for(InputField inputField : inputFields) {
            String inputName = inputField.getName();

            Object rawValue = userArguments.get(inputName.toString());
            if (inputField.getDataType().toString().equals("double")){
                inputValue = inputField.prepare(rawValue).asDouble();
            } else if (inputField.getDataType().toString().equals("integer")){
                inputValue = inputField.prepare(rawValue).asInteger();
            }
            arguments.put(inputName, inputValue);
        }
        //Map<String, Double> features = new HashMap<>();

        // Evaluate the model
        Map<String, ?> results = evaluator.evaluate(arguments);

        // Extracting prediction
        /*Map<String, Double> resultRecord = EvaluatorUtil.decodeAll(results);
        Double yPred = (Double) resultRecord.get(targetName.toString());
        MachineLearn machineLearn = new MachineLearn();
        machineLearn.accuracy = yPred;
        machineLearn.label = resultRecord.toString();
        //Double accuracy = resultRecord.
        //MachineLearn(resultRecord, yPred);
        System.out.printf("Prediction is %d\n", yPred);
        System.out.printf("PMML output %s\n", resultRecord);*/
    }
}
