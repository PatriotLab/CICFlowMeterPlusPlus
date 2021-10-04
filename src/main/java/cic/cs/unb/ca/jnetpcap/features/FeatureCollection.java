package cic.cs.unb.ca.jnetpcap.features;

import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;

import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.function.Supplier;

/**
 * Collection of features used to analyze packet captures and provide identifying information.
 */
public abstract class FeatureCollection {
    protected Field[] fields;

    /**
     * FeatureCollections may use this function to recursively process information about incoming packets.
     *
     * @param packet packet information to process
     */
    public void onPacket(BasicPacketInfo packet) {
    }


    /**
     * Get an array of strings representing the field's headers
     */
    public final String[] getHeader() {
        return Arrays.stream(fields)
                .map(f -> f.header)
                .toArray(String[]::new);
    }

    /**
     * Get the values of all the fields in this Feature collection
     */
    public final String[] getData() {
        return Arrays.stream(fields)
                .map(f -> f.supplier.get())
                .toArray(String[]::new);
    }

    /**
     * A builder of Fields for the feature collection.
     *
     * <p>All extending classes should build an array of Fields in their constructor and assign it to {@link FeatureCollection#fields}
     */
    static class FieldBuilder {
        private final ArrayList<Field> fields = new ArrayList<Field>() {
        };

        /**
         * Add a new subfeature's field and rename with the format string.
         *
         * @param subfeature FeatureCollection to include as a subfeature
         * @param format     MessageFormat style formatting string
         */
        public FieldBuilder addField(FeatureCollection subfeature, String format) {
            for (Field field : subfeature.fields) {
                fields.add(field.addFormat(format));
            }
            return this;
        }

        /**
         * Add a new subfeature's fields without renaming.
         *
         * @param subfeature {@link FeatureCollection} to include as a subfeature
         * @see #addField(cic.cs.unb.ca.jnetpcap.features.FeatureCollection, java.lang.String)
         */
        public FieldBuilder addField(FeatureCollection subfeature) {
            fields.addAll(Arrays.asList(subfeature.fields));
            return this;
        }

        /**
         * Add a single field with a fixed name.
         *
         * @param supplier {@link Supplier} to get the value of the field when needed
         * @param name     Name of the field
         */
        public FieldBuilder addField(Supplier<Object> supplier, String name) {
            fields.add(new Field(name, () -> supplier.get().toString()));
            return this;
        }

        /**
         * Finish building the fields of your FeatureCollection to an array.
         *
         * @return an array of fields representing your feature collection
         */
        public Field[] build() {
            return this.fields.toArray(new Field[]{});
        }
    }

    /**
     * Represents a field's headers and a supplier that allow the user to get the field's current value.
     */
    private static final class Field {
        public final String header;
        public final Supplier<String> supplier;

        public Field(String header, Supplier<String> supplier) {
            this.header = header;
            this.supplier = supplier;
        }


        /**
         * Create a new Field as copy of the current one but with the name modified via the format string.
         * @param format MessageFormat-style formatting string to modify the name of the field
         * @return a new Field with modified name
         */
        public Field addFormat(String format) {
            return new Field(MessageFormat.format(format, header), supplier);
        }
    }
}

