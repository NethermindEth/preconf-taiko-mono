import requests
import json
import argparse

# Set up argument parser
parser = argparse.ArgumentParser(description="Send JSON-RPC requests to a specified method and port.")
parser.add_argument("method", type=str, help="The RPC method to call.")
parser.add_argument("port", type=int, help="The port to use for the RPC server.")
args = parser.parse_args()

# Define the URL of the JSON-RPC server
url = f"http://localhost:{args.port}/rpc"

# Define the headers
headers = {
    "Content-Type": "application/json",
}

# Define the payload for the specified method
payload = {
    "jsonrpc": "2.0",
    "method": args.method,
    "params": [ {"xLists": []}],
    "id": 1,
}

# Print the payload for verification
print("Payload:", json.dumps(payload, indent=4))

# Send the request
response = requests.post(url, headers=headers, data=json.dumps(payload))
print(f"Response: {response.text}")

if response.status_code != 200:
    print(f"Error: {response.status_code}")
else:
    print("Request was successful.")

print(str(response))
