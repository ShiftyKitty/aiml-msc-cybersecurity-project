# src/api/models.py
from pydantic import BaseModel, ConfigDict
from typing import Optional, List # Import List if needed, though not used here
from datetime import datetime

# Pydantic model for data coming INTO the /log endpoint's request body
# client_ip will be taken from the request object itself, not the body
class ApiLogCreate(BaseModel):
    endpoint: str
    method: str

# Pydantic model for representing a log entry read FROM the database
# Used as the response model for the /log endpoint
class ApiLogDisplay(BaseModel):
    # Use model_config in Pydantic v2 to enable ORM mode / from_attributes
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    endpoint: str
    method: str
    client_ip: str

# ---------------------------------------------------------------------------
# CORRECTED Model representing the input features for the /predict endpoint
# Based on the top 15 features used in the final model training
# ---------------------------------------------------------------------------
class PredictionFeaturesInput(BaseModel):
    # Verify data types (int/float) based on your df_selected DataFrame in the notebook
    Flow_IAT_Max: float
    Flow_Duration: int
    Bwd_Pkt_Len_Max: float
    ACK_Flag_Cnt: int
    Dst_Port: int
    TotLen_Fwd_Pkts: float
    PSH_Flag_Cnt: int
    Bwd_IAT_Max: float
    Tot_Fwd_Pkts: int
    Flow_IAT_Mean: float
    Init_Bwd_Win_Byts: int
    Flow_IAT_Min: float
    Fwd_Pkt_Len_Max: float
    RST_Flag_Cnt: int
    Pkt_Len_Var: float

    # Add model_config for potential extra fields if needed, though usually not for input
    # model_config = ConfigDict(extra='ignore') # or 'allow'

# Model for the prediction response
class PredictionOutput(BaseModel):
    is_anomalous: bool
    anomaly_score: float
    threshold_used: float
    warning_level: str  # Add this new field
    message: str