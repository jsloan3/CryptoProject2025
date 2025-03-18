import requests

hostname = "http://127.0.0.1:5000/register"

to_send = {"PhoneNum" : "444-444-4444", "Name" : "John Smith", "EdPublic" : "thisisapublickey"}

server_response = requests.post(hostname, json=to_send)
print(server_response)