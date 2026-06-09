# Webtransport_Test
Testing code on the server.

```
python3 server.py --cert certs/cert_ec.pem --key certs/key_ec.pem 
python3 -m http.server 8000
python3 client.py --url https://localhost:8443/wt --topic /cmd_vel --insecure
```
