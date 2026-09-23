"""Offline Technocore receipt inspection. Never requires a private key."""
import argparse, base64, hashlib, json, re
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
    room = data['room']
    if not isinstance(room, str) or not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,47}', room):
        raise ValueError('Invalid room')
    seen, rows = set(), []
    for r in data['messages']:
        state = verify(room, r)
        identity = json.dumps([room, r.get('from'), str(r.get('nonce')), r.get('text'), r.get('sig')], ensure_ascii=False, separators=(',', ':'))
        digest = hashlib.sha256(identity.encode()).hexdigest()
        rows.append({'seq':r.get('seq'), 'signature':state, 'envelope_sha256':digest, 'duplicate_envelope':digest in seen})
        seen.add(digest)
    return {'room':room, 'generation_observed':data.get('generation'), 'records':len(rows), 'verified':sum(r['signature']=='verified' for r in rows), 'invalid':sum(r['signature']=='invalid' for r in rows), 'not_reverifiable':sum(r['signature']=='not_reverifiable' for r in rows), 'duplicate_envelopes':sum(r['duplicate_envelope'] for r in rows), 'limitation':'seq, ts and generation are server metadata, not covered by the author signature. No completeness or publication-time proof is claimed.', 'results':rows}

if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('export');p.add_argument('--out', required=True);a=p.parse_args()
    raw=Path(a.export).read_bytes(); report=inspect(json.loads(raw));report['source_sha256']=hashlib.sha256(raw).hexdigest()
    Path(a.out).write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='results'}))
