
# API Security Model v2.0

## Model Information
- Type: Isolation Forest
- Version: v2.0
- Created: 2025-04-27 13:41:01
- Threshold: -0.085186

## Performance Metrics
| Metric | Value |
|--------|-------|
| Precision | 0.5455 |
| Recall | 1.0000 |
| F1 Score | 0.7059 |

## Features
The model uses the following features with their respective transformations and importance:

| Feature | Transformation | Importance |
|---------|---------------|------------|
| Pkt_Size_Ratio | none | 0.680000 |
| Bwd IAT Min | log1p | 0.566667 |
| ECE Flag Cnt | log1p | 0.000000 |
| Flow IAT Std | log1p | 0.000000 |
| Bwd Pkt Len Min | log1p | 0.000000 |
| FIN Flag Cnt | log1p | 0.000000 |
| Fwd PSH Flags | log1p | 0.000000 |

## Usage
This model is part of the API security system and is used to detect anomalous API requests.
It uses an Isolation Forest algorithm to identify requests that deviate from normal patterns.

## Preprocessing
Features should be preprocessed according to the transformation details provided in the metadata.
Refer to the preprocessing_components.json file for specific parameters.

## Interpretation
The model outputs an anomaly score for each request. Lower scores indicate more anomalous requests.
A threshold of -0.085186 is used to classify requests as normal or anomalous.

## Recommendations
1. Monitor model performance regularly
2. Retrain periodically with new data
3. Consider ensemble approaches for improved accuracy
