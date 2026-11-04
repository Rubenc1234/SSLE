reverter estado de jijacking:
curl -X POST http://localhost:5050/register \
-H "Content-Type: application/json" \
-d '{
  "service_id": "storage-001",
  "name": "storage-service",
  "url": "http://localhost:5002",
  "type": "storage",
  "region": "aveiro",
  "country": "pt",
  "dc": "dc1",
  "rack": "r01",
  "node": "n01"
}'
