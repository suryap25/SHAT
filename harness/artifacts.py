"""Content addressing and atomic publication on the local Linux filesystem."""
import hashlib
import json
import os
import tempfile
from pathlib import Path


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def crash(point):
    if os.environ.get('AHS_TEST_CRASH') == point:
        os._exit(137)


def publish(directory, data):
    """Temp -> fsync -> rename. Existing content is checked, never overwritten."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / (sha(data) + '.json')
    if target.exists():
        if target.read_bytes() != data:
            raise ValueError('digest/content mismatch; quarantine before retry')
        return target
    fd, temporary = tempfile.mkstemp(prefix='.part-', dir=directory)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(data[:len(data)//2])
            output.flush()
            crash('mid_artifact_write')
            output.write(data[len(data)//2:])
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
        fd = os.open(directory, os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        return target
    finally:
        Path(temporary).unlink(missing_ok=True)


def reconcile_artifacts(directory):
    directory = Path(directory)
    if not directory.exists():
        return []
    moved = []
    for path in list(directory.iterdir()):
        if not path.is_file():
            continue
        invalid = path.name.startswith('.part-') or (path.suffix == '.json' and path.stem != sha(path.read_bytes()))
        if invalid:
            quarantine = directory / 'quarantine'
            quarantine.mkdir(exist_ok=True)
            destination = quarantine / (path.name + '-' + sha(path.read_bytes()))
            os.replace(path, destination)
            moved.append(path.name)
    return moved
