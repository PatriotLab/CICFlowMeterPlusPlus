package cic.cs.unb.ca.jnetpcap.features;

import jakarta.xml.bind.JAXBException;
import org.jpmml.evaluator.*;
import org.sparkproject.dmg.pmml.FieldName;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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

    public FlowPrediction predict(FlowFeatures rowData) {

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

        double highest_prob = 0.0;
        String device_name = null;
        for(Map.Entry<String, ?> result : resultRecord.entrySet()){
            String key = result.getKey();
            Object val = result.getValue();
            if(val instanceof Double){
                Double probablility = (Double)result.getValue();
                if(probablility >= highest_prob){
                    device_name = key;
                    highest_prob = probablility;
                }
            }
        }

        return new FlowPrediction(device_name, highest_prob, rowData);
    }
}
