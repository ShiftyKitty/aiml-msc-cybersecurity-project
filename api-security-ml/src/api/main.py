# api/main.py
import logging
import joblib  # <--- Import joblib
import pandas as pd  # <--- Import pandas
import json
import os
from fastapi import FastAPI, Request, HTTPException, Depends
from sqlalchemy.sql import insert, update  # <--- Import update (needed if updating logs, though not used yet)
from fastapi.middleware.cors import CORSMiddleware

# Import engine, table definition
from src.api.database import engine, api_logs_table

# Import the Pydantic models including the new input model
from src.api.models import ApiLogCreate, ApiLogDisplay, PredictionFeaturesInput, PredictionOutput

try:
    from src.api.feature_preprocessing import FeaturePreprocessor
    FEATURE_PREPROCESSOR_AVAILABLE = True
except ImportError:
    FEATURE_PREPROCESSOR_AVAILABLE = False
    # Define a simple implementation in case the module doesn't exist
    class SimpleFeaturePreprocessor:
        def preprocess(self, features_dict):
            """Basic implementation that just returns the features"""
            return features_dict, "No preprocessing applied", True
    FeaturePreprocessor = SimpleFeaturePreprocessor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(title="API Security ML PoC", version="0.1.0")

# Add CORS middleware to allow frontend access if needed
app.add_middleware(
   CORSMiddleware,
   allow_origins=["*"],  # Specify allowed origins in production
   allow_credentials=True,
   allow_methods=["*"],
   allow_headers=["*"],
)

# # --- Global Variables / Model Loading ---
# MODEL_PATH = "src/models/api_security_model_v2.joblib"  # Update to v2
# METADATA_PATH = "src/models/model_metadata_v2.json"  # Update to v2
# # Update threshold to match your Phase 2 findings
# PREDICTION_THRESHOLD = -0.085186

# MODEL_PATH = "src/models/api_security_model.joblib"  
# METADATA_PATH = "src/models/model_metadata.json" 
# Load the optimal threshold found during tuning
# PREDICTION_THRESHOLD = -0.07928  

# Higher threshold for real life scenario
# PREDICTION_THRESHOLD = -0.06  

# --- Global Variables / Model Loading ---
# Original model path (Phase 1)
MODEL_PATH_V1 = "src/models/api_security_model.joblib"
METADATA_PATH_V1 = "src/models/model_metadata.json"
PREDICTION_THRESHOLD_V1 = -0.06  # Phase 1 threshold

# New model path (Phase 2)
MODEL_PATH_V2 = "src/models/api_security_model_v2.joblib"  # Updated model path
METADATA_PATH_V2 = "src/models/model_metadata_v2.json"  # Updated metadata path
PREDICTION_THRESHOLD_V2 = -0.085186  # Optimized threshold from Phase 2

# Use V2 model by default
MODEL_PATH = MODEL_PATH_V2  
METADATA_PATH = METADATA_PATH_V2
PREDICTION_THRESHOLD = PREDICTION_THRESHOLD_V2

# Set to True to use Phase 1 model instead of Phase 2
USE_PHASE1_MODEL = True  # Can be changed if needed for testing/comparison
if USE_PHASE1_MODEL:
    MODEL_PATH = MODEL_PATH_V1
    METADATA_PATH = METADATA_PATH_V1
    PREDICTION_THRESHOLD = PREDICTION_THRESHOLD_V1
    logger.info("Using Phase 1 model configuration")
else:
    logger.info("Using Phase 2 model configuration")

model = None
model_metadata = None  # Will store feature list and other model info
feature_preprocessor = None  # Will store the preprocessor instance

# Define feature validation limits (Phase 1 features)
FEATURE_LIMITS = {
   "Flow IAT Max": {"min": 0, "max": 1e8},
   "Flow Duration": {"min": 0, "max": 1e8},
   "Bwd Pkt Len Max": {"min": 0, "max": 1e5},
   "ACK Flag Cnt": {"min": 0, "max": 1e3},
   "Dst Port": {"min": 0, "max": 65535},
   "TotLen Fwd Pkts": {"min": 0, "max": 1e6},
   "PSH Flag Cnt": {"min": 0, "max": 1e3},
   "Bwd IAT Max": {"min": 0, "max": 1e8},
   "Tot Fwd Pkts": {"min": 0, "max": 1e6},
   "Flow IAT Mean": {"min": 0, "max": 1e8},
   "Init Bwd Win Byts": {"min": 0, "max": 1e6},
   "Flow IAT Min": {"min": 0, "max": 1e8},
   "Fwd Pkt Len Max": {"min": 0, "max": 1e5},
   "RST Flag Cnt": {"min": 0, "max": 1e3},
   "Pkt Len Var": {"min": 0, "max": 1e7}
}

FEATURE_LIMITS.update({
   "ECE Flag Cnt": {"min": 0, "max": 1e3},
   "Bwd IAT Min": {"min": 0, "max": 1e8},
   "Flow IAT Std": {"min": 0, "max": 1e8},
   "Pkt_Size_Ratio": {"min": 0, "max": 100},
   "Bwd Pkt Len Min": {"min": 0, "max": 1e5},
   "FIN Flag Cnt": {"min": 0, "max": 1e3},
   "Fwd PSH Flags": {"min": 0, "max": 1e3},
})

@app.on_event("startup")
async def startup_event():
   global model, model_metadata, feature_preprocessor  # Make sure all variables are global
   logger.info("FastAPI application starting up...")
   
   if engine is None:
       logger.error("Database engine is not initialized.")
   else:
       logger.info("Database engine initialized.")

   # Load the machine learning model
   try:
       logger.info(f"Loading model from: {MODEL_PATH}")
       model = joblib.load(MODEL_PATH)
       logger.info("Model loaded successfully.")
       
       # Load model metadata if available
       try:
           if os.path.exists(METADATA_PATH):
               with open(METADATA_PATH, 'r') as f:
                   model_metadata = json.load(f)
               logger.info(f"Model metadata loaded successfully: {len(model_metadata.get('features', [])) or 0} features found")
           else:
               logger.warning(f"Model metadata file not found at {METADATA_PATH}")
               model_metadata = {"features": [], "threshold": PREDICTION_THRESHOLD}
       except Exception as e:
           logger.error(f"Error loading model metadata: {e}", exc_info=True)
           model_metadata = {"features": [], "threshold": PREDICTION_THRESHOLD}
           
       # Initialize feature preprocessor (NEW)
       try:
           if FEATURE_PREPROCESSOR_AVAILABLE:
               feature_preprocessor = FeaturePreprocessor()
               logger.info("Feature preprocessor initialized successfully")
           else:
               logger.warning("Using simple feature preprocessor (limited functionality)")
               feature_preprocessor = FeaturePreprocessor()
       except Exception as e:
           logger.error(f"Error initializing feature preprocessor: {e}", exc_info=True)
           feature_preprocessor = None
           
   except FileNotFoundError:
       logger.error(f"Model file not found at {MODEL_PATH}. Prediction endpoint will fail.")
       model = None
   except Exception as e:
       logger.error(f"Error loading model: {e}", exc_info=True)
       model = None

# --- Shutdown Handler ---
@app.on_event("shutdown")
async def shutdown_event():
   logger.info("FastAPI application shutting down.")


# --- Root Endpoint ---
@app.get("/", summary="Health Check", tags=["General"])
async def read_root():
   logger.info("Root endpoint '/' accessed.")
   return {
       "message": "API Security ML PoC is running.",
       "model_version": "Phase 2" if not USE_PHASE1_MODEL else "Phase 1",
       "model_path": MODEL_PATH,
       "threshold": PREDICTION_THRESHOLD
   }


# --- NEW: Model Metadata Endpoint ---
@app.get("/model-info/", summary="Get Model Information", tags=["Model"])
async def get_model_info():
   """
   Returns information about the currently loaded model, including:
   - Features used by the model
   - Detection threshold
   - Feature importance values if available
   """
   logger.info("Model info endpoint accessed.")
   
   if model is None:
       logger.error("Model is not loaded. Cannot provide model info.")
       raise HTTPException(status_code=503, detail="Model not available")
       
   # Prepare model info response
   info = {
       "model_type": "Isolation Forest",
       "threshold": PREDICTION_THRESHOLD,
       "features": model_metadata.get("features", []) if model_metadata else [],
       "feature_importance": model_metadata.get("feature_importance", {}) if model_metadata else {},
       "status": "loaded" if model is not None else "not_loaded"
   }
   
   return info

# --- Model Metadata Endpoint ---
@app.get("/model-info/", summary="Get Model Information", tags=["Model"])
async def get_model_info():
   """
   Returns information about the currently loaded model, including:
   - Features used by the model
   - Detection threshold
   - Feature importance values if available
   """
   logger.info("Model info endpoint accessed.")
   
   if model is None:
       logger.error("Model is not loaded. Cannot provide model info.")
       raise HTTPException(status_code=503, detail="Model not available")
       
   # Prepare model info response
   info = {
       "model_type": "Isolation Forest",
       "model_version": "Phase 2" if not USE_PHASE1_MODEL else "Phase 1",
       "threshold": PREDICTION_THRESHOLD,
       "features": model_metadata.get("features", []) if model_metadata else [],
       "feature_importance": model_metadata.get("feature_importance", {}) if model_metadata else {},
       "status": "loaded" if model is not None else "not_loaded"
   }
   
   return info


# --- Logging Endpoint ---
@app.post("/log/",
         response_model=ApiLogDisplay,
         status_code=201,
         summary="Log Basic API Request Info",
         tags=["Logging"])
async def log_api_request(request_data: ApiLogCreate, request: Request):
   if engine is None:
        logger.error("Database connection not available for /log/ endpoint.")
        raise HTTPException(status_code=503, detail="Database connection not available")

   client_ip = request.client.host if request.client else "unknown"
   logger.info(f"Received request for /log/: Endpoint={request_data.endpoint}, Method={request_data.method}, Client IP={client_ip}")

   log_entry_values = {
       "endpoint": request_data.endpoint,
       "method": request_data.method,
       "client_ip": client_ip
   }
   query = insert(api_logs_table).values(**log_entry_values).returning(api_logs_table)

   try:
       with engine.connect() as connection:
           result = connection.execute(query)
           connection.commit()
           created_log = result.fetchone()
           if created_log:
               logger.info(f"Successfully logged request with ID: {created_log.id}")
               return created_log._mapping
           else:
               logger.error("Failed to retrieve created log entry after insert.")
               raise HTTPException(status_code=500, detail="Failed to retrieve created log entry")
   except Exception as e:
       logger.error(f"Error logging request to database: {e}", exc_info=True)
       raise HTTPException(status_code=500, detail="Database interaction error occurred.")


# --- NEW: Feature Validation Function ---
def validate_features(features_dict):
    """
    Validates that all required features are present and within expected ranges.
    
    Args:
        features_dict: Dictionary of feature names (with spaces) and values
        
    Returns:
        Tuple of (is_valid, message)
    """
    # Define core Phase 1 features (these are required)
    core_features = [
        "Flow IAT Max", "Flow Duration", "Bwd Pkt Len Max", "ACK Flag Cnt", 
        "Dst Port", "TotLen Fwd Pkts", "PSH Flag Cnt", "Bwd IAT Max", 
        "Tot Fwd Pkts", "Flow IAT Mean", "Init Bwd Win Byts", "Flow IAT Min", 
        "Fwd Pkt Len Max", "RST Flag Cnt", "Pkt Len Var"
    ]
    
    # Check if all required core features are present
    missing_core_features = [feature for feature in core_features if feature not in features_dict]
    if missing_core_features:
        return False, f"Missing required core features: {', '.join(missing_core_features)}"
    
    # Phase 2 features are optional - we can create them
    missing_phase2_features = [
        feature for feature in FEATURE_LIMITS.keys() 
        if feature not in features_dict and feature not in core_features
    ]
    
    # Check if features are within expected ranges
    out_of_range_features = []
    for feature, value in features_dict.items():
        if feature in FEATURE_LIMITS:
            limits = FEATURE_LIMITS[feature]
            if value < limits["min"] or value > limits["max"]:
                out_of_range_features.append(f"{feature} ({value} not in range {limits['min']}-{limits['max']})")
    
    if out_of_range_features:
        return False, f"Features out of expected range: {', '.join(out_of_range_features)}"
    
    # Return validation success, with a note if there are missing Phase 2 features
    message = "All features valid"
    if missing_phase2_features:
        message += f". Note: Missing Phase 2 features will be computed: {', '.join(missing_phase2_features)}"
    
    return True, message
    
# --- Create Composite Features Function (NEW) ---
def create_composite_features(features_dict):
    """
    Creates composite features based on original features.
    This function provides a fallback in case FeaturePreprocessor is not available.
    
    Args:
        features_dict: Dictionary of feature values
        
    Returns:
        Dictionary with added composite features
    """
    try:
        # Create a copy to avoid modifying input
        result = features_dict.copy()
        
        # Add Pkt_Size_Ratio (most important feature from Phase 2)
        if 'Fwd Pkt Len Max' in result and 'Bwd Pkt Len Max' in result:
            result['Pkt_Size_Ratio'] = result['Fwd Pkt Len Max'] / (result['Bwd Pkt Len Max'] + 1)
        
        # Add IAT_Ratio
        if 'Flow IAT Max' in result and 'Flow IAT Min' in result:
            result['IAT_Ratio'] = result['Flow IAT Max'] / (result['Flow IAT Min'] + 1)
        
        # Add Flag_Combination
        if all(f in result for f in ['ACK Flag Cnt', 'PSH Flag Cnt', 'RST Flag Cnt']):
            result['Flag_Combination'] = (result['ACK Flag Cnt'] + 
                                         2*result['PSH Flag Cnt'] + 
                                         4*result['RST Flag Cnt'])
        
        # Add Pkts_Per_Second
        if 'Tot Fwd Pkts' in result and 'Flow Duration' in result:
            result['Pkts_Per_Second'] = result['Tot Fwd Pkts'] / (result['Flow Duration'] / 1000000 + 0.001)
        
        # Add attack-specific scores
        if 'RST Flag Cnt' in result and 'Bwd Pkt Len Max' in result:
            result['SQL_Injection_Score'] = result['RST Flag Cnt'] * result['Bwd Pkt Len Max'] / 100
        
        if 'TotLen Fwd Pkts' in result and 'Tot Fwd Pkts' in result:
            result['Brute_Force_Score'] = result['TotLen Fwd Pkts'] * result['Tot Fwd Pkts'] / 1000
        
        if all(f in result for f in ['TotLen Fwd Pkts', 'Tot Fwd Pkts', 'Pkt Len Var']):
            result['XSS_Score'] = (result['TotLen Fwd Pkts'] * 
                                  result['Tot Fwd Pkts'] * 
                                  result['Pkt Len Var'] / 1000000)
        
        return result
    except Exception as e:
        logger.warning(f"Error creating composite features: {e}")
        return features_dict  # Return original if there's an error


# --- Prediction Endpoint (UPDATED) ---
# --- Prediction Endpoint (UPDATED) ---
@app.post("/predict/", 
        response_model=PredictionOutput,
        summary="Predict Anomaly Score for Request Features",
        tags=["Prediction"])
async def predict_request_anomaly(features_input: PredictionFeaturesInput, request: Request):
  """
  Receives request features (simulated network flow features),
  runs the pre-loaded Isolation Forest model, logs the result,
  and returns the anomaly status and score based on a pre-defined threshold.
  """
  client_ip = request.client.host if request.client else "unknown"
  logger.info(f"Received request for /predict/ from IP: {client_ip}")

  if model is None:
      logger.error("Model is not loaded. Cannot perform prediction.")
      raise HTTPException(status_code=503, detail="Model not available")
  if engine is None:
       logger.error("Database connection not available for /predict/ endpoint.")
       raise HTTPException(status_code=503, detail="Database connection not available")

  # --- 1. Prepare Features ---
  try:
      # Convert Pydantic model to dictionary
      features_dict = features_input.model_dump()

      # Transform feature names: replace underscores with spaces to match training data
      transformed_dict = {k.replace('_', ' '): v for k, v in features_dict.items()}
      
      # Create composite features (Phase 2 enhancement)
      if feature_preprocessor is not None:
          # Use the feature preprocessor if available
          processed_dict, validation_msg, is_valid = feature_preprocessor.preprocess(transformed_dict)
          if not is_valid:
              logger.warning(f"Feature preprocessing warning: {validation_msg}")
          transformed_dict = processed_dict
      else:
          # Fallback to basic validation and composite feature creation
          is_valid, validation_msg = validate_features(transformed_dict)
          if not is_valid:
              logger.warning(f"Feature validation failed: {validation_msg}")
              raise ValueError(f"Feature validation failed: {validation_msg}")
          
          # Create composite features manually if preprocessor is not available
          transformed_dict = create_composite_features(transformed_dict)
      
      # Get required features for the model
      required_features = model_metadata.get('features', [])
      if not required_features:
          # If metadata doesn't have features, use all available
          features_for_model = transformed_dict
      else:
          # Filter to just the required features
          features_for_model = {k: v for k, v in transformed_dict.items() if k in required_features}
          
          # Check if we have all required features
          missing_features = [f for f in required_features if f not in features_for_model]
          if missing_features:
              logger.warning(f"Missing required features for model: {missing_features}")
              # Try to continue with available features
      
      # Convert dictionary to Pandas DataFrame
      features_df = pd.DataFrame([features_for_model])
      
      logger.info(f"Feature transformation complete. Features: {list(features_df.columns)}")

  except ValueError as ve:
      # Specific handling for validation errors
      logger.error(f"Validation error: {ve}")
      raise HTTPException(status_code=400, detail=str(ve))
  except Exception as e:
       logger.error(f"Error preparing features from input: {e}", exc_info=True)
       raise HTTPException(status_code=400, detail="Invalid feature data format or structure.")

  # --- 2. Predict ---
  try:
      # Get required features in the correct order from metadata
      required_features = model_metadata.get('features', [])
      
      if not required_features:
          # If no metadata features found, this is a problem
          logger.warning("No feature list found in model metadata. Cannot ensure correct feature order.")
          features_for_prediction = features_df
      else:
          # Create a new DataFrame with columns in the exact order expected by the model
          features_for_prediction = pd.DataFrame(columns=required_features)
          
          # Fill one row with default values
          features_for_prediction.loc[0] = [0.0] * len(required_features)
          
          # Update with actual values where available
          for feature in required_features:
              if feature in features_df.columns:
                  features_for_prediction[feature] = features_df[feature].values[0]
          
          logger.info(f"Reordered features to match model training order: {list(features_for_prediction.columns)}")
      
      # Use the correctly-ordered DataFrame for prediction
      scores = model.decision_function(features_for_prediction)
      anomaly_score = float(scores[0])  # Get score for the single prediction

      # Classify based on the threshold (score <= threshold == anomalous)
      is_anomalous = anomaly_score <= PREDICTION_THRESHOLD

      # Add warning level calculation
      warning_level = "none"
      if anomaly_score <= PREDICTION_THRESHOLD:
          warning_level = "high"
      elif anomaly_score <= (PREDICTION_THRESHOLD + 0.02):
          warning_level = "medium"
      elif anomaly_score <= (PREDICTION_THRESHOLD + 0.04):
          warning_level = "low"

      logger.info(f"Prediction complete: Score={anomaly_score:.6f}, Is Anomalous={is_anomalous}, Warning Level={warning_level} (Threshold={PREDICTION_THRESHOLD})")

  except ValueError as ve:
      # Handle specific scikit-learn errors
      logger.error(f"Model prediction value error: {ve}", exc_info=True)
      raise HTTPException(status_code=400, detail=f"Model prediction error: {str(ve)}")
  except Exception as e:
      logger.error(f"Error during model prediction: {e}", exc_info=True)
      raise HTTPException(status_code=500, detail="Model prediction failed.")

  # --- 3. Log Result to Database ---
  log_entry_values = {
      "endpoint": "/predict/",  # Using fixed endpoint for this log type
      "method": request.method,
      "client_ip": client_ip,
      "is_anomalous": is_anomalous,
      "anomaly_score": anomaly_score
      # Optional: "request_details": features_input.model_dump_json() # Log input features
  }
  log_query = insert(api_logs_table).values(**log_entry_values)

  try:
      with engine.connect() as connection:
          connection.execute(log_query)
          connection.commit()
      logger.info("Prediction result logged to database.")
  except Exception as e:
      logger.error(f"Error logging prediction result to database: {e}", exc_info=True)
      # Decide if prediction should fail if logging fails. Usually, we return the prediction anyway.

  # --- 4. Return Result ---
  # Determine detailed message based on anomaly score and attack patterns
  attack_type = "Unknown"
  message = "Normal traffic pattern detected"

  # Enhanced attack type detection with Phase 2 features
  if is_anomalous or warning_level != "none":
      # Check for high Pkt_Size_Ratio which was important in Phase 2
      if transformed_dict.get("Pkt_Size_Ratio", 0) > 5.0:
          attack_type = "Brute Force-Web"
      # Check for XSS patterns
      elif transformed_dict.get("TotLen Fwd Pkts", 0) > 6000 and transformed_dict.get("Tot Fwd Pkts", 0) > 30:
          attack_type = "Cross-Site Scripting (XSS)"
      # Check for SQL Injection patterns
      elif transformed_dict.get("RST Flag Cnt", 0) > 0 and transformed_dict.get("Bwd Pkt Len Max", 0) > 800:
          attack_type = "SQL Injection"
      # Check for Brute Force patterns
      elif transformed_dict.get("TotLen Fwd Pkts", 0) > 2000 or transformed_dict.get("Tot Fwd Pkts", 0) > 20:
          attack_type = "Brute Force"
      # Check if we have Bwd IAT Min signal (important in Phase 2)
      elif transformed_dict.get("Bwd IAT Min", 0) < 10:
          attack_type = "Potential Network Scanning"
      else:
          attack_type = "Unknown"
        
      # Create appropriate message
      if is_anomalous:
          message = f"Potential {attack_type} attack detected"
      else:
          message = f"Suspicious traffic pattern - possible {attack_type} characteristics"

  return PredictionOutput(
      is_anomalous=is_anomalous,
      anomaly_score=anomaly_score,
      threshold_used=PREDICTION_THRESHOLD,  # Include threshold for context
      warning_level=warning_level,  # New field
      message=message
  )