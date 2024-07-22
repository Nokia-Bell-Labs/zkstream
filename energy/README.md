## Data set

We downloaded the data set from https://debs.org/grand-challenges/2014/. This is a 24 GB zip file that extracts to a 136 GB CSV file.
We filtered out the values for plug id 0 in household 0 in house 0. We also only kept the values for the load property (property = 1).
The resulting filed is included here in data.csv. We used the following command:

    # Get load values (property = 1) from plug id = 0; household id = 0; house = 0.
    grep ',1,0,0,0$' sorted.csv > data.csv
