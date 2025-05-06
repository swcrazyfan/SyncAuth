import requests

api_key = "qiUFXJGyZcHbzAggn5R4xzFVW7pxYSte"
url = "http://host.docker.internal:8384/rest/system/status"

headers = {
    "X-API-Key": api_key
}

try:
    response = requests.get(url, headers=headers)
    
    print(f"Status Code: {response.status_code}")
    print(f"Response Headers: {dict(response.headers)}")
    
    if response.status_code == 200:
        print(f"Response Body: {response.json()}")
    else:
        print(f"Response Text: {response.text}")
        
except Exception as e:
    print(f"Error: {str(e)}")
