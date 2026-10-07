"""Run only inside the security harness sandbox."""
import json
import sys
sys.path.insert(0, '/source')
from records import safe_read, vulnerable_read

leaked = vulnerable_read('bob', 'invoice-a')['tenant'] == 'alice'
try:
    safe_read('bob', 'invoice-a')
    safe_denied = False
except PermissionError:
    safe_denied = True
assert safe_read('alice', 'invoice-a')['amount'] == 10
assert safe_denied, 'negative control failed'
print(json.dumps({'outcome': 'REPRODUCED' if leaked else 'NOT_REPRODUCED',
                  'observations': {'vulnerable_exposes_other_tenant': leaked,
                                   'safe_denies_other_tenant': safe_denied,
                                   'owner_read_succeeds': True}}))
