import numpy as np
import pandas as pd
import json
import os
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class FeaturePreprocessor:
    """
    Handles all feature preprocessing for the API security model
    including transformations, composite feature creation, and error handling
    """
    
    def __init__(self, config_path='src/models/preprocessing_components.json'):
        """
        Initialize the preprocessor with configuration
        
        Args:
            config_path: Path to the preprocessing configuration JSON
        """
        try:
            # Load configuration
            if not os.path.exists(config_path):
                raise FileNotFoundError(f"Preprocessing configuration not found at {config_path}")
                
            with open(config_path, 'r') as f:
                self.config = json.load(f)
                
            # Extract components
            self.feature_cols = self.config.get('feature_cols', [])
            self.transformations = self.config.get('transformations', {})
            self.range_info = self.config.get('range_info', {})
            
            logger.info(f"FeaturePreprocessor initialized with {len(self.feature_cols)} features")
            
        except Exception as e:
            logger.error(f"Error initializing FeaturePreprocessor: {e}")
            # Set defaults
            self.feature_cols = []
            self.transformations = {}
            self.range_info = {}
            raise
    
    def transform_features(self, features_dict):
        """
        Apply all necessary transformations to input features
        
        Args:
            features_dict: Dictionary of feature values
            
        Returns:
            Transformed feature dictionary
        """
        try:
            # Create copy to avoid modifying input
            transformed = features_dict.copy()
            
            # Apply defined transformations
            for feature, transform_type in self.transformations.items():
                if feature in transformed:
                    if transform_type == 'log':
                        transformed[feature] = np.log1p(max(0, transformed[feature]))
                    elif transform_type == 'minmax':
                        if feature in self.range_info:
                            min_val = self.range_info[feature]['min']
                            max_val = self.range_info[feature]['max']
                            if max_val > min_val:
                                transformed[feature] = (transformed[feature] - min_val) / (max_val - min_val)
            
            # Create composite features
            transformed = self.create_composite_features(transformed)
            
            return transformed
            
        except Exception as e:
            logger.error(f"Error transforming features: {e}")
            # Return original features if transformation fails
            return features_dict
    
    def create_composite_features(self, features_dict):
        """
        Create all composite features needed by the model
        
        Args:
            features_dict: Dictionary of feature values
            
        Returns:
            Enhanced feature dictionary with composite features
        """
        try:
            # Add ratio features
            if 'Fwd Pkt Len Max' in features_dict and 'Bwd Pkt Len Max' in features_dict:
                features_dict['Pkt_Size_Ratio'] = features_dict['Fwd Pkt Len Max'] / (features_dict['Bwd Pkt Len Max'] + 1)
            
            # Add timing ratios
            if 'Flow IAT Max' in features_dict and 'Flow IAT Min' in features_dict:
                features_dict['IAT_Ratio'] = features_dict['Flow IAT Max'] / (features_dict['Flow IAT Min'] + 1)
            
            # Add flag combinations
            if all(f in features_dict for f in ['ACK Flag Cnt', 'PSH Flag Cnt', 'RST Flag Cnt']):
                features_dict['Flag_Combination'] = (features_dict['ACK Flag Cnt'] + 
                                                    2*features_dict['PSH Flag Cnt'] + 
                                                    4*features_dict['RST Flag Cnt'])
            
            # Add packet count normalized by duration
            if 'Tot Fwd Pkts' in features_dict and 'Flow Duration' in features_dict:
                features_dict['Pkts_Per_Second'] = features_dict['Tot Fwd Pkts'] / (features_dict['Flow Duration'] / 1000000 + 0.001)
            
            # Add attack-specific scores
            if 'RST Flag Cnt' in features_dict and 'Bwd Pkt Len Max' in features_dict:
                features_dict['SQL_Injection_Score'] = features_dict['RST Flag Cnt'] * features_dict['Bwd Pkt Len Max'] / 100
            
            if 'TotLen Fwd Pkts' in features_dict and 'Tot Fwd Pkts' in features_dict:
                features_dict['Brute_Force_Score'] = features_dict['TotLen Fwd Pkts'] * features_dict['Tot Fwd Pkts'] / 1000
            
            if all(f in features_dict for f in ['TotLen Fwd Pkts', 'Tot Fwd Pkts', 'Pkt Len Var']):
                features_dict['XSS_Score'] = (features_dict['TotLen Fwd Pkts'] * 
                                             features_dict['Tot Fwd Pkts'] * 
                                             features_dict['Pkt Len Var'] / 1000000)
            
            return features_dict
            
        except Exception as e:
            logger.error(f"Error creating composite features: {e}")
            # Return original features if creation fails
            return features_dict
    
    def validate_features(self, features_dict):
        """
        Validate features against defined limits and handle missing values
        
        Args:
            features_dict: Dictionary of feature values
            
        Returns:
            Tuple of (is_valid, validated_dict, message)
        """
        try:
            validated = {}
            missing_features = []
            out_of_range_features = []
            
            # Check for missing required features
            for feature in self.feature_cols:
                if feature not in features_dict:
                    # Use median value if feature is missing
                    if feature in self.range_info and 'median' in self.range_info[feature]:
                        validated[feature] = self.range_info[feature]['median']
                        missing_features.append(feature)
                    else:
                        # If we don't have median, use 0
                        validated[feature] = 0
                        missing_features.append(feature)
                else:
                    validated[feature] = features_dict[feature]
            
            # Handle out-of-range values
            for feature in validated:
                if feature in self.range_info:
                    # Get min and max values from training
                    min_val = self.range_info[feature]['min']
                    max_val = self.range_info[feature]['max']
                    
                    # Check if value is out of range
                    if validated[feature] < min_val:
                        validated[feature] = min_val
                        out_of_range_features.append((feature, 'below', validated[feature], min_val))
                    elif validated[feature] > max_val:
                        validated[feature] = max_val
                        out_of_range_features.append((feature, 'above', validated[feature], max_val))
            
            # Create validation message
            message = ""
            if missing_features:
                message += f"Missing features: {', '.join(missing_features)}. Using default values. "
            
            if out_of_range_features:
                message += "Out-of-range features: "
                for feature, direction, value, limit in out_of_range_features:
                    message += f"{feature} ({value} {direction} {limit}), "
                message = message.rstrip(", ") + ". Values clipped to training range."
            
            is_valid = not (missing_features or out_of_range_features)
            
            return is_valid, validated, message
            
        except Exception as e:
            logger.error(f"Error validating features: {e}")
            return False, features_dict, f"Validation error: {str(e)}"
    
    def preprocess(self, features_dict):
        """
        Complete preprocessing pipeline: validate, transform, and create composite features
        
        Args:
            features_dict: Dictionary of feature values
            
        Returns:
            Tuple of (processed_dict, validation_message, is_valid)
        """
        try:
            # Step 1: Validate and handle missing/out-of-range values
            is_valid, validated_dict, validation_message = self.validate_features(features_dict)
            
            # Step 2: Transform features
            transformed_dict = self.transform_features(validated_dict)
            
            # Step 3: Create composite features
            processed_dict = self.create_composite_features(transformed_dict)
            
            # Return processed data with validation info
            return processed_dict, validation_message, is_valid
            
        except Exception as e:
            logger.error(f"Error in preprocessing pipeline: {e}")
            return features_dict, f"Preprocessing error: {str(e)}", False

# For direct testing
if __name__ == "__main__":
    # Test the preprocessor
    preprocessor = FeaturePreprocessor()
    
    # Example feature dictionary
    test_features = {
        "Flow_IAT_Max": 5000000.0,
        "Flow_Duration": 7000000,
        "Bwd_Pkt_Len_Max": 500.0,
        "ACK_Flag_Cnt": 0,
        "Dst_Port": 80,
        "TotLen_Fwd_Pkts": 3500.0,
        "PSH_Flag_Cnt": 1,
        "Bwd_IAT_Max": 4800000.0,
        "Tot_Fwd_Pkts": 25,
        "Flow_IAT_Mean": 400000.0,
        "Init_Bwd_Win_Byts": 230,
        "Flow_IAT_Min": 30.0,
        "Fwd_Pkt_Len_Max": 350.0,
        "RST_Flag_Cnt": 1,
        "Pkt_Len_Var": 50000.0
    }
    
    # Convert underscores to spaces to match model training format
    test_features_spaces = {k.replace('_', ' '): v for k, v in test_features.items()}
    
    # Process the features
    processed, message, is_valid = preprocessor.preprocess(test_features_spaces)
    
    print(f"Validation status: {is_valid}")
    print(f"Validation message: {message}")
    print("\nProcessed features:")
    for feature, value in processed.items():
        print(f"{feature}: {value}")