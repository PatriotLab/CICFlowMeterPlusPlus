package cic.cs.unb.ca.jnetpcap.features;
import jakarta.xml.bind.JAXBException;
//import org.apache.log4j.MDC;
//import org.dmg.pmml.FieldName;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
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
//    private InputField .;

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

        HashMap<String, String> featureData = new HashMap<>();
        String[] headers = rowData.getHeader();
        String[] values = rowData.getData();
        for(int i = 0; i < headers.length; i++){
            featureData.put(headers[i], values[i]);
        }

        Map<String, FieldValue> arguments = new LinkedHashMap<>();
        List<InputField> inputFields = evaluator.getInputFields();

        //Iterate through, adding the column entries into the arguments
        //Hang on, we don't need column names, do we?

        for(InputField inputField : inputFields) {
            String inputName = inputField.getName();
            String dataValue = featureData.get(inputName);

            if (inputField.getDataType().toString().equals("double")){
                FieldValue fieldValue = inputField.prepare(Double.parseDouble(dataValue));
                arguments.put(inputName, fieldValue);
            } else if (inputField.getDataType().toString().equals("integer")){
                FieldValue fieldValue = inputField.prepare(Integer.parseInt(dataValue));
                arguments.put(inputName, fieldValue);
            }
        }
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
