"""
Feature engineering module for API security anomaly detection.
"""
import pandas as pd
import numpy as np
from collections import defaultdict

def create_time_features(df, timestamp_col='timestamp'):
    """
    Create time-based features from timestamp column.
    
    Parameters:
    -----------
    df : pandas.DataFrame
        DataFrame containing API logs
    timestamp_col : str
        Name of the timestamp column
        
    Returns:
    --------
    pandas.DataFrame
        DataFrame with added time features
    """
    df = df.copy()
    
    # Convert timestamp to datetime if not already
    if not pd.api.types.is_datetime64_any_dtype(df[timestamp_col]):
        df[timestamp_col] = pd.to_datetime(df[timestamp_col])
    
    # Extract time components
    df['hour'] = df[timestamp_col].dt.hour
    df['day_of_week'] = df[timestamp_col].dt.dayofweek
    df['is_weekend'] = df['day_of_week'].isin([5, 6]).astype(int)
    df['is_business_hours'] = ((df['hour'] >= 9) & (df['hour'] < 17) & 
                              ~df['is_weekend']).astype(int)
    
    return df

def calculate_request_velocity(df, group_cols=['ip_address'], timestamp_col='timestamp'):
    """
    Calculate request velocity (time between consecutive requests) for groups.
    
    Parameters:
    -----------
    df : pandas.DataFrame
        DataFrame containing API logs
    group_cols : list
        Columns to group by (e.g., ['ip_address'] or ['ip_address', 'user_id'])
    timestamp_col : str
        Name of the timestamp column
        
    Returns:
    --------
    pandas.DataFrame
        DataFrame with added velocity features
    """
    df = df.copy()
    
    # Convert timestamp to datetime if not already
    if not pd.api.types.is_datetime64_any_dtype(df[timestamp_col]):
        df[timestamp_col] = pd.to_datetime(df[timestamp_col])
    
    # Sort by group and timestamp
    sort_cols = group_cols + [timestamp_col]
    df = df.sort_values(sort_cols)
    
    # Calculate time delta between consecutive requests
    df['prev_timestamp'] = df.groupby(group_cols)[timestamp_col].shift(1)
    df['time_delta_seconds'] = (df[timestamp_col] - df['prev_timestamp']).dt.total_seconds()
    
    # Replace NaN with a large value for the first request in each group
    df['time_delta_seconds'] = df['time_delta_seconds'].fillna(86400)  # 24 hours in seconds
    
    # Calculate additional velocity metrics for each group
    velocity_features = []
    
    for name, group in df.groupby(group_cols):
        if len(group) < 2:
            continue
            # Calculate velocity metrics
        metrics = {
            'request_count': len(group),
            'mean_time_delta': group['time_delta_seconds'].mean(),
            'min_time_delta': group['time_delta_seconds'].min(),
            'median_time_delta': group['time_delta_seconds'].median(),
            'std_time_delta': group['time_delta_seconds'].std(),
        }
        
        # Calculate rapid request sequences (requests within 1 second of each other)
        rapid_requests = (group['time_delta_seconds'] < 1).sum()
        metrics['rapid_request_count'] = rapid_requests
        metrics['rapid_request_ratio'] = rapid_requests / len(group)
        
        # Add group identifiers
        for i, col in enumerate(group_cols):
            if isinstance(name, tuple):
                metrics[col] = name[i]
            else:
                metrics[col] = name
                
        velocity_features.append(metrics)
    
    # Create velocity features DataFrame
    if velocity_features:
        velocity_df = pd.DataFrame(velocity_features)
        
        # Merge back with original DataFrame
        df = df.merge(velocity_df, on=group_cols, how='left')
    
    return df

def extract_endpoint_patterns(df, endpoint_col='endpoint'):
    """
    Extract patterns from API endpoints.
    
    Parameters:
    -----------
    df : pandas.DataFrame
        DataFrame containing API logs
    endpoint_col : str
        Name of the endpoint column
        
    Returns:
    --------
    pandas.DataFrame
        DataFrame with added endpoint pattern features
    """
    df = df.copy()
    
    # Extract endpoint base path (without IDs)
    df['endpoint_base'] = df[endpoint_col].str.split('/').apply(
        lambda x: '/'.join([part for part in x if not ('{' in part and '}' in part)])
    )
    
    # Extract resource type (e.g., 'users', 'products')
    df['resource_type'] = df[endpoint_col].str.split('/').apply(
        lambda x: [part for part in x if part and part not in ['api', '{id}']][0] 
        if len([part for part in x if part]) > 1 else 'unknown'
    )
    
    return df

def calculate_error_rates(df, group_cols=['ip_address'], status_col='status_code'):
    """
    Calculate error rates for different groups.
    
    Parameters:
    -----------
    df : pandas.DataFrame
        DataFrame containing API logs
    group_cols : list
        Columns to group by (e.g., ['ip_address'] or ['user_id'])
    status_col : str
        Name of the HTTP status code column
        
    Returns:
    --------
    pandas.DataFrame
        DataFrame with added error rate features
    """
    df = df.copy()
    
    # Define error status codes
    client_errors = [400, 401, 403, 404]
    server_errors = [500, 501, 502, 503, 504]
    
    # Add error flags
    df['is_client_error'] = df[status_col].isin(client_errors).astype(int)
    df['is_server_error'] = df[status_col].isin(server_errors).astype(int)
    df['is_auth_failure'] = ((df[status_col] == 401) | (df[status_col] == 403)).astype(int)
    
    # Calculate error rates by group
    error_features = []
    
    for name, group in df.groupby(group_cols):
        total_requests = len(group)
        
        metrics = {
            'request_count': total_requests,
            'client_error_count': group['is_client_error'].sum(),
            'server_error_count': group['is_server_error'].sum(),
            'auth_failure_count': group['is_auth_failure'].sum(),
        }
        
        # Calculate rates
        metrics['client_error_rate'] = metrics['client_error_count'] / total_requests
        metrics['server_error_rate'] = metrics['server_error_count'] / total_requests
        metrics['auth_failure_rate'] = metrics['auth_failure_count'] / total_requests
        
        # Add group identifiers
        for i, col in enumerate(group_cols):
            if isinstance(name, tuple):
                metrics[col] = name[i]
            else:
                metrics[col] = name
                
        error_features.append(metrics)
    
    # Create error features DataFrame
    if error_features:
        error_df = pd.DataFrame(error_features)
        
        # Merge back with original DataFrame
        df = df.merge(error_df, on=group_cols, how='left')
    
    return df

def build_feature_matrix(df, interval_minutes=10, group_cols=['ip_address']):
    """
    Build feature matrix for anomaly detection from raw API logs.
    Aggregates data into time windows to create a matrix where each row
    represents activities within a specific time window.
    
    Parameters:
    -----------
    df : pandas.DataFrame
        DataFrame containing API logs
    interval_minutes : int
        Size of the time window in minutes
    group_cols : list
        Columns to group by for feature aggregation
        
    Returns:
    --------
    pandas.DataFrame
        Feature matrix ready for anomaly detection
    """
    # Ensure timestamp is datetime
    df = df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
        df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Create time window
    df['time_window'] = df['timestamp'].dt.floor(f'{interval_minutes}min')
    
    # Group by time window and other grouping columns
    window_group_cols = ['time_window'] + group_cols
    grouped = df.groupby(window_group_cols)
    
    # Aggregate features
    feature_matrix = grouped.agg({
        'request_count': 'first',  # These should be calculated earlier
        'client_error_rate': 'first',
        'server_error_rate': 'first',
        'auth_failure_rate': 'first',
        'rapid_request_ratio': 'first',
        'mean_time_delta': 'first',
        'min_time_delta': 'first',
        'response_time_ms': ['mean', 'max', 'std'],
        'query_time_ms': ['mean', 'max', 'std', 'count'],
    }).reset_index()
    
    # Flatten multi-level column names
    feature_matrix.columns = [
        '_'.join(col).strip('_') for col in feature_matrix.columns.values
    ]
    
    # Add one-hot