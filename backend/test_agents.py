from app.services.spec_parser import SpecParser
from app.orchestrator import Orchestrator
import json

# load sample spec
with open("../sample-api/openapi.json") as f:
    spec = json.load(f)

parser = SpecParser()
parsed = parser.parse_spec(spec)

orch = Orchestrator()
result = orch.run_all(parsed)

print(result)
