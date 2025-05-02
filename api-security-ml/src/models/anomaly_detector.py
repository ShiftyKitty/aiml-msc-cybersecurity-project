"""
Base anomaly detection model for API security.
"""
import numpy as np
import pandas as pd
from pyod.models.iforest import IForest
from pyod.models.lof import LOF
from pyod.models.auto_encoder import AutoEncoder
from sklearn.preprocessing import StandardScaler
import joblib
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class APIAnomalyDetector:
    """
    Machine learning-based anomaly detection for RESTful API security.
    This class provides methods to train, save, load, and use various anomaly
    detection algorithms to identify suspicious API traffic patterns.
    """
    
    def __init__(self, model_type='iforest', model_params=None):
        """
        Initialize the anomaly detector.
        
        Parameters:
        -----------
        model_type : str
            Type of anomaly detection model to use. Options:
            - 'iforest': Isolation Forest (default)
            - 'lof': Local Outlier Factor
            - 'autoencoder': AutoEncoder Neural Network
        
        model_params : dict or None
            Parameters to pass to the model constructor
        """
        self.model_type = model_type
        self.model_params = model_params or {}
        self.model = None
        self.scaler = StandardScaler()
        
    def _create_model(self):
        """Create the anomaly detection model based on model_type."""
        if self.model_type == 'iforest':
            return IForest(
                contamination=self.model_params.get('contamination', 0.05),
                random_state=self.model_params.get('random_state', 42),
                **{k: v for k, v in self.model_params.items() 
                  if k not in ['contamination', 'random_state']}
            )
        elif self.model_type == 'lof':
            return LOF(
                contamination=self.model_params.get('contamination', 0.05),
                **{k: v for k, v in self.model_params.items() if k != 'contamination'}
            )
        elif self.model_type == 'autoencoder':
            return AutoEncoder(
                contamination=self.model_params.get('contamination', 0.05),
                hidden_neurons=self.model_params.get('hidden_neurons', [64, 32, 32, 64]),
                epochs=self.model_params.get('epochs', 100),
                **{k: v for k, v in self.model_params.items() 
                  if k not in ['contamination', 'hidden_neurons', 'epochs']}
            )
        else:
            raise ValueError(f"Unsupported model type: {self.model_type}")
    
    def fit(self, X, y=None):
        """
        Train the anomaly detection model.
        
        Parameters:
        -----------
        X : array-like or DataFrame
            Training data with features
        y : array-like, optional (unused, included for API compatibility)
            Target values (not used for unsupervised anomaly detection)
            
        Returns:
        --------
        self : object
            Fitted estimator
        """
        # Scale the features
        X_scaled = self.scaler.fit_transform(X)
        
        # Create and fit the model
        self.model = self._create_model()
        self.model.fit(X_scaled)
        
        logger.info(f"Trained {self.model_type} model on {X.shape[0]} samples with {X.shape[1]} features")
        return self
    
    def predict(self, X):
        """
        Predict if instances are anomalies.
        
        Parameters:
        -----------
        X : array-like or DataFrame
            Data with features
            
        Returns:
        --------
        y_pred : array
            Binary labels (1: anomaly, 0: normal)
        """
        if self.model is None:
            raise ValueError("Model not fitted. Call fit() first.")
        
        # Scale the features
        X_scaled = self.scaler.transform(X)
        
        # Predict anomalies
        return self.model.predict(X_scaled)
    
    def decision_function(self, X):
        """
        Get anomaly scores for instances.
        
        Parameters:
        -----------
        X : array-like or DataFrame
            Data with features
            
        Returns:
        --------
        scores : array
            Anomaly scores (higher = more anomalous)
        """
        if self.model is None:
            raise ValueError("Model not fitted. Call fit() first.")
        
        # Scale the features
        X_scaled = self.scaler.transform(X)
        
        # Get anomaly scores
        return self.model.decision_function(X_scaled)
    
    def save(self, model_dir):
        """
        Save the trained model and scaler to files.
        
        Parameters:
        -----------
        model_dir : str
            Directory to save the model files
        """
        if self.model is None:
            raise ValueError("Model not fitted. Call fit() first.")
        
        # Create the directory if it doesn't exist
        os.makedirs(model_dir, exist_ok=True)
        
        # Save the model
        joblib.dump(self.model, os.path.join(model_dir, 'model.pkl'))
        
        # Save the scaler
        joblib.dump(self.scaler, os.path.join(model_dir, 'scaler.pkl'))
        
        # Save model type and params
        pd.Series({
            'model_type': self.model_type,
            'model_params': str(self.model_params)
        }).to_csv(os.path.join(model_dir, 'metadata.csv'))
        
        logger.info(f"Model saved to {model_dir}")
    
    @classmethod
    def load(cls, model_dir):
        """
        Load a trained model from files.
        
        Parameters:
        -----------
        model_dir : str
            Directory containing the model files
            
        Returns:
        --------
        model : APIAnomalyDetector
            Loaded model
        """
        # Load metadata
        metadata = pd.read_csv(os.path.join(model_dir, 'metadata.csv'), index_col=0).squeeze()
        model_type = metadata['model_type']
        
        # Create a new instance
        detector = cls(model_type=model_type)
        
        # Load the model
        detector.model = joblib.load(os.path.join(model_dir, 'model.pkl'))
        
        # Load the scaler
        detector.scaler = joblib.load(os.path.join(model_dir, 'scaler.pkl'))
        
        logger.info(f"Loaded {model_type} model from {model_dir}")
        return detector