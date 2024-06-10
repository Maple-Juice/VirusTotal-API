import requests
import pandas as pd
from virustotal_API_key import api_key

def query_virustotal(hash_value):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return extract_info(data)
    else:
        return None

def extract_info(data):
    attributes = data['data']['attributes']
    file_hashes = {
        "SHA256": attributes['sha256'],
        "MD5": attributes['md5'],
        "SHA1": attributes['sha1']
    }
    detections = attributes['last_analysis_stats']['malicious']
    antivirus_detected = {key: val['result'] for key, val in attributes['last_analysis_results'].items() if val['category'] == 'malicious'}
    names = ", ".join(attributes['names'])

    return {
        "File Hashes": file_hashes,
        "Detections": detections,
        "Antivirus Names": list(antivirus_detected.keys()),
        "File Names": names
    }

def save_to_csv(data, filename='Malware_Report.csv'):
    df = pd.DataFrame(data)
    df.to_csv(filename, index=False)
    return filename

def process_alerts(file_path):
    alert_df = pd.read_csv(file_path)
    malware_alerts_df = alert_df[alert_df['Alert'] == "Malware detected"]
    results = []

    for _, row in malware_alerts_df.iterrows():
        hash_value = row['HashValue']
        result = query_virustotal(hash_value)
        if result:
            results.append(result)
    
    if results:
        filename = save_to_csv(results)
        print(f"Data saved in {filename}")
    else:
        print("No malware alerts found or failed to retrieve data.")

