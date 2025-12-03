# modules/cloud_sync.py
import requests
import threading

# The address of your local "Cloud" server
CLOUD_URL = "http://127.0.0.1:8000/api/v1/sync/scan"

def sync_scan_to_cloud(api_key, device_name, ip, threat_level, details):
    """
    Background thread to push scan results to the cloud.
    """
    def _send():
        payload = {
            "device_name": device_name,
            "ip_address": ip,
            "threat_level": threat_level,
            "details": details
        }
        
        try:
            # We pass the API Key as a Query Parameter for simplicity in this MVP
            # (In production, this goes in the Header)
            url = f"{CLOUD_URL}?api_key={api_key}"
            
            response = requests.post(url, json=payload, timeout=5)
            
            if response.status_code == 200:
                print(f"☁️ Cloud Sync Success: {device_name}")
            else:
                print(f"⚠️ Cloud Sync Failed: {response.text}")
                
        except Exception as e:
            print(f"❌ Cloud Connection Error: {e}")

    # Run in background so it doesn't freeze the UI
    threading.Thread(target=_send, daemon=True).start()