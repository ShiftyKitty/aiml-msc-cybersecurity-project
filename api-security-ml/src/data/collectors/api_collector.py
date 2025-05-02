"""
Module for collecting and processing API traffic data.
"""
import json
import datetime
import time
import pandas as pd
import logging
from flask import Flask, request, jsonify
import threading
import queue
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class APITrafficCollector:
    """
    Collects API traffic data for anomaly detection.
    
    This class provides methods to:
    1. Act as a proxy for collecting API request/response data
    2. Simulate API traffic for testing
    3. Load data from existing log files
    """
    
    def __init__(self, output_dir='../../data/raw'):
        """
        Initialize the collector.
        
        Parameters:
        -----------
        output_dir : str
            Directory to save collected data
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.data_queue = queue.Queue()
        self.collection_active = False
        self.collector_thread = None
    
    def start_proxy_server(self, host='0.0.0.0', port=5000, target_api=None):
        """
        Start a Flask server to act as a proxy for collecting API traffic.
        
        Parameters:
        -----------
        host : str
            Host to bind the server to
        port : int
            Port to bind the server to
        target_api : str
            Base URL of the target API to proxy requests to
        """
        app = Flask(__name__)
        
        @app.before_request
        def log_request():
            """Log the request before processing."""
            timestamp = datetime.datetime.now()
            
            # Extract request data
            data = {
                'timestamp': timestamp.isoformat(),
                'endpoint': request.path,
                'method': request.method,
                'ip_address': request.remote_addr,
                'headers': dict(request.headers),
                'params': dict(request.args),
                'user_agent': request.headers.get('User-Agent', '')
            }
            
            # Extract body if available
            if request.is_json:
                data['body'] = request.get_json()
            
            # Store request data for later processing
            request.request_data = data
            
        @app.after_request
        def log_response(response):
            """Log the response after processing."""
            timestamp = datetime.datetime.now()
            
            # Get request data and add response info
            data = request.request_data
            data['response_status'] = response.status_code
            data['response_timestamp'] = timestamp.isoformat()
            data['response_time_ms'] = (datetime.datetime.fromisoformat(data['response_timestamp']) - 
                                       datetime.datetime.fromisoformat(data['timestamp'])).total_seconds() * 1000
            
            # Add to queue for processing
            self.data_queue.put(data)
            
            return response
        
        # Start the collector thread if not already running
        if not self.collection_active:
            self.collection_active = True
            self.collector_thread = threading.Thread(target=self._process_queue)
            self.collector_thread.daemon = True
            self.collector_thread.start()
        
        # Start the Flask server
        logger.info(f"Starting API proxy server on {host}:{port}")
        app.run(host=host, port=port)
    
    def _process_queue(self):
        """Process the data queue and save to files periodically."""
        data_buffer = []
        last_save_time = time.time()
        
        while self.collection_active:
            try:
                # Get data from queue with timeout
                data = self.data_queue.get(timeout=1)
                data_buffer.append(data)
                
                # Save buffer every 100 items or 60 seconds
                current_time = time.time()
                if len(data_buffer) >= 100 or (current_time - last_save_time) >= 60:
                    self._save_data(data_buffer)
                    data_buffer = []
                    last_save_time = current_time
                    
                self.data_queue.task_done()
            except queue.Empty:
                # No data in queue, check if we should save buffer
                if data_buffer and (time.time() - last_save_time) >= 60:
                    self._save_data(data_buffer)
                    data_buffer = []
                    last_save_time = time.time()
        
        # Save any remaining data when stopping
        if data_buffer:
            self._save_data(data_buffer)
    
    def _save_data(self, data_buffer):
        """Save collected data to file."""
        if not data_buffer:
            return
            
        # Create filename based on current timestamp
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = os.path.join(self.output_dir, f'api_traffic_{timestamp}.json')
        
        # Save to file
        with open(filename, 'w') as f:
            json.dump(data_buffer, f)
            
        logger.info(f"Saved {len(data_buffer)} records to {filename}")
    
    def stop_collection(self):
        """Stop the data collection process."""
        self.collection_active = False
        if self.collector_thread:
            self.collector_thread.join(timeout=5)
        logger.info("Stopped API traffic collection")
    
    @staticmethod
    def load_data(file_paths):
        """
        Load API traffic data from files.
        
        Parameters:
        -----------
        file_paths : str or list
            Path(s) to data file(s)
            
        Returns:
        --------
        pandas.DataFrame
            DataFrame containing API traffic data
        """
        if isinstance(file_paths, str):
            file_paths = [file_paths]
            
        data_list = []
        
        for file_path in file_paths:
            # Determine file type
            if file_path.endswith('.json'):
                with open(file_path, 'r') as f:
                    file_data = json.load(f)
                data_list.extend(file_data)
            elif file_path.endswith('.csv'):
                df = pd.read_csv(file_path)
                data_list.extend(df.to_dict('records'))
            else:
                logger.warning(f"Unsupported file type: {file_path}")
        
        # Convert to DataFrame
        if data_list:
            df = pd.DataFrame(data_list)
            logger.info(f"Loaded {len(df)} records from {len(file_paths)} files")
            return df
        else:
            logger.warning("No data loaded")
            return pd.DataFrame()