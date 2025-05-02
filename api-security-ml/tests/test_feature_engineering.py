# Save as tests/test_feature_engineering.py

import os
import sys
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# Add the src directory to path for importing modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.api.feature_preprocessing import FeaturePreprocessor

def test_feature_preprocessing():
    """Test the feature preprocessing module with sample data"""
    # Initialize preprocessor
    preprocessor = FeaturePreprocessor()
    
    # Load test samples
    test_samples_path = 'data/processed/enhanced_features_dataset.csv'
    if not os.path.exists(test_samples_path):
        print(f"Test samples not found at {test_samples_path}")
        # Use sample data
        test_samples = create_test_samples()
    else:
        test_samples = pd.read_csv(test_samples_path)
        test_samples = test_samples.sample(min(10, len(test_samples)), random_state=42)
    
    # Process each sample and verify results
    for i, sample in test_samples.iterrows():
        print(f"\nTesting sample {i+1}:")
        
        # Convert to dictionary
        sample_dict = {col: sample[col] for col in sample.index 
                       if col not in ['is_attack', 'attack_type', 'Label']}
        
        # Process the sample
        processed, message, is_valid = preprocessor.preprocess(sample_dict)
        
        print(f"Validation status: {is_valid}")
        print(f"Validation message: {message}")
        
        # Check composite features
        composite_features = [f for f in processed if f not in sample_dict]
        print(f"Composite features created: {len(composite_features)}")
        if composite_features:
            for feature in composite_features[:5]:  # Show first 5
                print(f"- {feature}: {processed[feature]}")
        
        # Check for any errors or unexpected values
        for feature, value in processed.items():
            if np.isnan(value) or np.isinf(value):
                print(f"Warning: Feature '{feature}' has invalid value: {value}")

def create_test_samples():
    """Create test samples for different attack types"""
    test_samples = pd.DataFrame()
    
    # Normal sample
    normal_sample = {
        "Flow IAT Max": 5872510.0,
        "Flow Duration": 5934505.0,
        "Bwd Pkt Len Max": 231.0,
        "ACK Flag Cnt": 0,
        "Dst Port": 80,
        "TotLen Fwd Pkts": 1100.0,
        "PSH Flag Cnt": 1,
        "Bwd IAT Max": 4000000.0,
        "Tot Fwd Pkts": 9,
        "Flow IAT Mean": 300000.0,
        "Init Bwd Win Byts": 250,
        "Flow IAT Min": 50.0,
        "Fwd Pkt Len Max": 400.0,
        "RST Flag Cnt": 0,
        "Pkt Len Var": 10000.0,
        "attack_type": "Normal",
        "is_attack": False
    }
    
    # SQL Injection sample
    sql_injection_sample = {
        "Flow IAT Max": 3850000.0,
        "Flow Duration": 4500000,
        "Bwd Pkt Len Max": 1200.0,
        "ACK Flag Cnt": 0,
        "Dst Port": 80,
        "TotLen Fwd Pkts": 1100.0,
        "PSH Flag Cnt": 1,
        "Bwd IAT Max": 4000000.0,
        "Tot Fwd Pkts": 9,
        "Flow IAT Mean": 300000.0,
        "Init Bwd Win Byts": 250,
        "Flow IAT Min": 50.0,
        "Fwd Pkt Len Max": 400.0,
        "RST Flag Cnt": 1,
        "Pkt Len Var": 75000.0,
        "attack_type": "SQL Injection",
        "is_attack": True
    }
    
    # Brute Force-Web sample
    brute_force_web_sample = {
        "Flow IAT Max": 5000000.0,
        "Flow Duration": 7000000,
        "Bwd Pkt Len Max": 500.0,
        "ACK Flag Cnt": 0,
        "Dst Port": 80,
        "TotLen Fwd Pkts": 3500.0,
        "PSH Flag Cnt": 1,
        "Bwd IAT Max": 4800000.0,
        "Tot Fwd Pkts": 25,
        "Flow IAT Mean": 400000.0,
        "Init Bwd Win Byts": 230,
        "Flow IAT Min": 30.0,
        "Fwd Pkt Len Max": 350.0,
        "RST Flag Cnt": 0,
        "Pkt Len Var": 50000.0,
        "attack_type": "Brute Force-Web",
        "is_attack": True
    }
    
    # Brute Force-XSS sample
    brute_force_xss_sample = {
        "Flow IAT Max": 4500000.0,
        "Flow Duration": 5500000,
        "Bwd Pkt Len Max": 900.0,
        "ACK Flag Cnt": 0,
        "Dst Port": 80,
        "TotLen Fwd Pkts": 7000.0,
        "PSH Flag Cnt": 1,
        "Bwd IAT Max": 4500000.0,
        "Tot Fwd Pkts": 35,
        "Flow IAT Mean": 350000.0,
        "Init Bwd Win Byts": 260,
        "Flow IAT Min": 25.0,
        "Fwd Pkt Len Max": 380.0,
        "RST Flag Cnt": 0,
        "Pkt Len Var": 100000.0,
        "attack_type": "Brute Force-XSS",
        "is_attack": True
    }
    
    # Add samples to DataFrame
    samples = [normal_sample, sql_injection_sample, brute_force_web_sample, brute_force_xss_sample]
    for sample in samples:
        test_samples = pd.concat([test_samples, pd.DataFrame([sample])], ignore_index=True)
    
    return test_samples

if __name__ == "__main__":
    print("Testing Feature Engineering Implementation")
    test_feature_preprocessing()
    print("\nFeature Engineering tests completed.")