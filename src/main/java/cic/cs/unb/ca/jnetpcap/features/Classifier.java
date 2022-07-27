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
        FieldValue fieldValue;
        String inputName;
        String dataValue;

        //Iterate through, adding the column entries into the arguments LinkedHashMap

        for(InputField inputField : inputFields) {
            inputName = inputField.getName();
            dataValue = featureData.get(inputName);

            if (inputField.getDataType().toString().equals("double")){
                fieldValue = inputField.prepare(Double.parseDouble(dataValue));
                arguments.put(inputName, fieldValue);
            } else if (inputField.getDataType().toString().equals("integer")){
                fieldValue = inputField.prepare(Integer.parseInt(dataValue));
                arguments.put(inputName, fieldValue);
            }
        }

        // Evaluate the model
        Map<String, ?> results = evaluator.evaluate(arguments);

        // Extract prediction
        Map<String, ?> resultRecord = EvaluatorUtil.decodeAll(results);
        MachineLearn machineLearn = new MachineLearn();

        //We need to iterate through the map resultRecord to find the key/value where the value is 1.0. The key value will be the predicted label.
        machineLearn.label = results.
                //(String) resultRecord.get(targetName.toString());
    }
}
