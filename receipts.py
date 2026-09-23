"""Offline Technocore receipt inspection. Never requires a private key."""
import argparse, base64, hashlib, json, re, sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def verify(room, record):
    if not record.get('sig'):
        return 'not_reverifiable'
    try:
        did, sig, nonce, text = (record[k] for k in ('from', 'sig', 'nonce', 'text'))
        if not isinstance(nonce, (str, int)) or isinstance(nonce, bool):
            return 'invalid'
        if not re.fullmatch(r'[0-9]{1,19}', str(nonce)) or not isinstance(text, str):
            return 'invalid'
        if not isinstance(did, str) or not did.startswith('did:key:z6Mk') or len(did) != 56:
            return 'invalid'
        n = 0
        for c in did[9:]:
            n = n * 58 + ALPHABET.index(c)
        raw = n.to_bytes(34, 'big')
        if raw[:2] != b'\xed\x01' or not re.fullmatch(r'[A-Za-z0-9_-]{86}', sig):
            return 'invalid'
        signature = base64.urlsafe_b64decode(sig + '==')
        if base64.urlsafe_b64encode(signature).decode().rstrip('=') != sig:
            return 'invalid'
        Ed25519PublicKey.from_public_bytes(raw[2:]).verify(signature, f'{room}|{nonce}|{text}'.encode())
        return 'verified'
    except (ValueError, TypeError, KeyError, OverflowError):
        return 'invalid'
    except Exception as e:
        from cryptography.exceptions import InvalidSignature
        if isinstance(e, InvalidSignature):
            return 'invalid'
        raise

def inspect(data):
    if not isinstance(data, dict):
        raise ValueError('Export must be a JSON object')
    room = data.get('room')
    if not isinstance(room, str) or not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,47}', room):
        raise ValueError('Invalid room')
    messages = data.get('messages')
    if not isinstance(messages, list):
        raise ValueError('messages must be a JSON array')
    if any(not isinstance(record, dict) for record in messages):
        raise ValueError('Each message must be a JSON object')
    seen, rows = set(), []
    for r in messages:
        state = verify(room, r)
        identity = json.dumps([room, r.get('from'), str(r.get('nonce')), r.get('text'), r.get('sig')], ensure_ascii=False, separators=(',', ':'))
        digest = hashlib.sha256(identity.encode()).hexdigest()
        rows.append({'seq':r.get('seq'), 'signature':state, 'envelope_sha256':digest, 'duplicate_envelope':digest in seen})
        seen.add(digest)
    return {'room':room, 'generation_observed':data.get('generation'), 'records':len(rows), 'verified':sum(r['signature']=='verified' for r in rows), 'invalid':sum(r['signature']=='invalid' for r in rows), 'not_reverifiable':sum(r['signature']=='not_reverifiable' for r in rows), 'duplicate_envelopes':sum(r['duplicate_envelope'] for r in rows), 'limitation':'seq, ts and generation are server metadata, not covered by the author signature. No completeness or publication-time proof is claimed.', 'results':rows}

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('export')
    parser.add_argument('--out', required=True)
    parser.add_argument('--strict', action='store_true', help='Also fail on missing signatures or an empty export')
    args = parser.parse_args(argv)
    try:
        if Path(args.export).resolve() == Path(args.out).resolve():
            raise ValueError('Input and output must be different files')
        raw = Path(args.export).read_bytes()
        report = inspect(json.loads(raw))
        report['source_sha256'] = hashlib.sha256(raw).hexdigest()
        Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    except (ValueError, OSError) as error:
        print(f'Error: {error}', file=sys.stderr)
        return 2
    print(json.dumps({k: v for k, v in report.items() if k != 'results'}))
    return int(report['invalid'] > 0 or (args.strict and (report['not_reverifiable'] > 0 or report['records'] == 0)))

if __name__ == '__main__':
    sys.exit(main())
