package cic.cs.unb.ca.jnetpcap.features;
import jakarta.xml.bind.JAXBException;
//import org.apache.log4j.MDC;
//import org.dmg.pmml.FieldName;
import org.jpmml.evaluator.*;
import org.sparkproject.dmg.pmml.FieldName;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

public class LoadPMMLModel {
    public LoadPMMLModel(FlowFeatures flow) throws JAXBException, IOException, ParserConfigurationException, SAXException {
        main(flow);
    }

    public static void main(FlowFeatures rowData) throws JAXBException, IOException, SAXException, ParserConfigurationException {
        //Load PMML file
/*        String modelFolder = Objects.requireNonNull(LoadPMMLModel.class.getClassLoader().getResource("model")).getPath();
        String modelFolder = "/";
        String modelName = "DecisionTreeClassifier.pmml";
        Path modelPath = Paths.get(modelFolder, modelName);
        Path modelPath = Paths.get(modelPath, modelName);//This line will have the PMML selected from the FlowOfflinePane
*/
        //Prepare and verify PMML file
        Evaluator evaluator = new LoadingModelEvaluatorBuilder()
                .load(modelPath.toFile())
                .build();
        evaluator.verify();

        FieldName targetName = FieldName.create(evaluator.getTargetFields().get(0).getName());

        Map<String, ?> userArguments = (Map<String, ?>) rowData;
        Map<String, FieldValue> arguments = new LinkedHashMap<>();
        List<InputField> inputFields = evaluator.getInputFields();

        //Iterate through, adding the column entries into the arguments
        for(InputField inputField : inputFields) {
            String inputName = inputField.getName();
            Object rawValue = userArguments.get(inputName);
            FieldValue inputValue = inputField.prepare(rawValue);
            arguments.put(inputName, inputValue);
        }
        Map<String, Double> features = new HashMap<>();

        // Evaluate the model
        Map<String, ?> results = evaluator.evaluate(arguments);

        // Extracting prediction
        Map<String, ?> resultRecord = EvaluatorUtil.decodeAll(results);
        Integer yPred = (Integer) resultRecord.get(targetName.toString());
        //Double accuracy = resultRecord.
        //MachineLearn(resultRecord, yPred);
        System.out.printf("Prediction is %d\n", yPred);
        System.out.printf("PMML output %s\n", resultRecord);
    }
}
