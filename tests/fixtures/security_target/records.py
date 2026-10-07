"""Owned qualification fixture: deliberately vulnerable and safe variants."""
RECORDS = {'invoice-a': {'tenant': 'alice', 'amount': 10}}


def vulnerable_read(caller_tenant, record_id):
    return RECORDS[record_id]


def safe_read(caller_tenant, record_id):
    record = RECORDS[record_id]
    if record['tenant'] != caller_tenant:
        raise PermissionError('wrong tenant')
    return record
