package cic.cs.unb.ca.jnetpcap.features;

import org.apache.commons.math3.stat.descriptive.SummaryStatistics;

/**
 * FeatureCollection class wrapping a {@link SummaryStatistics}
 *
 * <p>Users should include this class like normal and build its field with a name indicating its usage. Values should be
 * added to the summary with the {@link #addValue(double)} method.
 *
 * <p>This feature collection currently has four fields: Maximum, Minimum, Mean, and Standard Deviation.
 * <p>The following features could potentially be added in the future: Geometric Mean, Number of Values, Sum, Sum of
 * Squares, and Variance.
 */
public class StatsFeature extends FeatureCollection {
    SummaryStatistics summary = new SummaryStatistics();

    public StatsFeature() {
        new FeatureCollection.FieldBuilder()
                .addField(() -> nanCheck(summary.getMax()), "Max")
                .addField(() -> nanCheck(summary.getMin()), "Min")
                .addField(() -> nanCheck(summary.getMean()), "Mean")
                .addField(() -> nanCheck(summary.getVariance()), "Variance")
                .addField(() -> nanCheck(summary.getStandardDeviation()), "Std")
                .addField(() -> nanCheck(summary.getSum()), "Total")
                .build(this);
    }

    // This is a hack to make sure that if there is no data, it will instead return zero
    private static double nanCheck(double val) {
        if(Double.isNaN(val)){
            return 0.0;
        } else {
            return val;
        }
    }

    /**
     * Add a value to the statistics summary.
     *
     * @param v Value to add to the summary
     */
    void addValue(double v) {
        summary.addValue(v);
    }
}
