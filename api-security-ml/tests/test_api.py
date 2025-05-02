import requests
import json

# Define API endpoint
api_url = "http://localhost:8000/predict/"

# Function to add Phase 2 features to samples
def add_phase2_features(sample):
    """Add required Phase 2 features to test samples"""
    sample = sample.copy()  # Create a copy to avoid modifying original
    
    # Add missing features with reasonable values
    sample.update({
        'ECE_Flag_Cnt': 0,
        'Bwd_IAT_Min': 50.0,
        'Flow_IAT_Std': 100000.0,
        # Pkt_Size_Ratio will be computed automatically
        'Bwd_Pkt_Len_Min': 10.0,
        'FIN_Flag_Cnt': 0,
        'Fwd_PSH_Flags': 1
    })
    return sample
    
# Normal traffic sample (converting feature names to match your API model)
normal_sample = {
    "Flow_IAT_Max": 5872510.0,
    "Flow_Duration": 5934505,
    "Bwd_Pkt_Len_Max": 231.0,
    "ACK_Flag_Cnt": 0,
    "Dst_Port": 80,
    "TotLen_Fwd_Pkts": 97.0,
    "PSH_Flag_Cnt": 1,
    "Bwd_IAT_Max": 5931101.0,
    "Tot_Fwd_Pkts": 4,
    "Flow_IAT_Mean": 847786.428571428,
    "Init_Bwd_Win_Byts": 141,
    "Flow_IAT_Min": 69.0,
    "Fwd_Pkt_Len_Max": 97.0,
    "RST_Flag_Cnt": 0,
    "Pkt_Len_Var": 6352.0277777778
}

# Attack traffic sample
attack_sample = {
    "Flow_IAT_Max": 4950591.0,
    "Flow_Duration": 6499677,
    "Bwd_Pkt_Len_Max": 1048.0,
    "ACK_Flag_Cnt": 0,
    "Dst_Port": 80,
    "TotLen_Fwd_Pkts": 2333.0,
    "PSH_Flag_Cnt": 1,
    "Bwd_IAT_Max": 5000999.0,
    "Tot_Fwd_Pkts": 13,
    "Flow_IAT_Mean": 295439.863636364,
    "Init_Bwd_Win_Byts": 269,
    "Flow_IAT_Min": 19.0,
    "Fwd_Pkt_Len_Max": 431.0,
    "RST_Flag_Cnt": 1,
    "Pkt_Len_Var": 85216.6884057971
}

# SQL Injection sample
sql_injection_sample = {
    "Flow_IAT_Max": 3850000.0,
    "Flow_Duration": 4500000,
    "Bwd_Pkt_Len_Max": 1200.0,
    "ACK_Flag_Cnt": 0,
    "Dst_Port": 80,
    "TotLen_Fwd_Pkts": 1100.0,
    "PSH_Flag_Cnt": 1,
    "Bwd_IAT_Max": 4000000.0,
    "Tot_Fwd_Pkts": 9,
    "Flow_IAT_Mean": 300000.0,
    "Init_Bwd_Win_Byts": 250,
    "Flow_IAT_Min": 50.0,
    "Fwd_Pkt_Len_Max": 400.0,
    "RST_Flag_Cnt": 1,
    "Pkt_Len_Var": 75000.0
}

# Brute Force-Web sample
brute_force_web_sample = {
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

# Brute Force-XSS sample
brute_force_xss_sample = {
    "Flow_IAT_Max": 4500000.0,
    "Flow_Duration": 5500000,
    "Bwd_Pkt_Len_Max": 900.0,
    "ACK_Flag_Cnt": 0,
    "Dst_Port": 80,
    "TotLen_Fwd_Pkts": 7000.0,
    "PSH_Flag_Cnt": 1,
    "Bwd_IAT_Max": 4500000.0,
    "Tot_Fwd_Pkts": 35,
    "Flow_IAT_Mean": 350000.0,
    "Init_Bwd_Win_Byts": 260,
    "Flow_IAT_Min": 25.0,
    "Fwd_Pkt_Len_Max": 380.0,
    "RST_Flag_Cnt": 1,
    "Pkt_Len_Var": 100000.0
}

# Add Phase 2 features to all samples
normal_sample = add_phase2_features(normal_sample)
attack_sample = add_phase2_features(attack_sample)
sql_injection_sample = add_phase2_features(sql_injection_sample)
brute_force_web_sample = add_phase2_features(brute_force_web_sample)
brute_force_xss_sample = add_phase2_features(brute_force_xss_sample)

# Test normal traffic
print("Testing normal traffic sample...")
response = requests.post(api_url, json=normal_sample)
print(f"Status Code: {response.status_code}")
print(f"Response: {json.dumps(response.json(), indent=2)}")

# Test attack traffic
print("\nTesting attack traffic sample...")
response = requests.post(api_url, json=attack_sample)
print(f"Status Code: {response.status_code}")
print(f"Response: {json.dumps(response.json(), indent=2)}")

# Test SQL Injection sample
print("\nTesting SQL Injection sample...")
response = requests.post(api_url, json=sql_injection_sample)
print(f"Status Code: {response.status_code}")
print(f"Response: {json.dumps(response.json(), indent=2)}")

# Test Brute Force-Web sample
print("\nTesting Brute Force-Web sample...")
response = requests.post(api_url, json=brute_force_web_sample)
print(f"Status Code: {response.status_code}")
print(f"Response: {json.dumps(response.json(), indent=2)}")

# Test Brute Force-XSS sample
print("\nTesting Brute Force-XSS sample...")
response = requests.post(api_url, json=brute_force_xss_sample)
print(f"Status Code: {response.status_code}")
print(f"Response: {json.dumps(response.json(), indent=2)}")