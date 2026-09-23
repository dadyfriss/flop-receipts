import base64, copy, unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from receipts import ALPHABET, inspect
class ReceiptsTests(unittest.TestCase):
    def setUp(self):
        key=Ed25519PrivateKey.generate();n=int.from_bytes(b'\xed\x01'+key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw),'big');s=''
        while n:n,r=divmod(n,58);s=ALPHABET[r]+s
        msg={'from':'did:key:z'+s,'nonce':9007199254740993,'text':'hello','seq':1,'ts':'observed'}
        msg['sig']=base64.urlsafe_b64encode(key.sign(f"test|{msg['nonce']}|hello".encode())).decode().rstrip('=')
        self.data={'room':'test','messages':[msg]}
    def test_valid_large_integer(self):self.assertEqual(inspect(self.data)['verified'],1)
    def test_tampered_text(self):
        self.data['messages'][0]['text']='changed';self.assertEqual(inspect(self.data)['invalid'],1)
    def test_other_room(self):
        self.data['room']='other';self.assertEqual(inspect(self.data)['invalid'],1)
    def test_missing_signature(self):
        del self.data['messages'][0]['sig'];self.assertEqual(inspect(self.data)['not_reverifiable'],1)
    def test_metadata_does_not_authenticate(self):
        self.data['messages'][0]['ts']='forged';self.assertEqual(inspect(self.data)['verified'],1)
    def test_duplicate(self):
        self.data['messages'].append(copy.deepcopy(self.data['messages'][0]));self.assertEqual(inspect(self.data)['duplicate_envelopes'],1)
    def test_float_nonce(self):
        self.data['messages'][0]['nonce']=9007199254740992.0;self.assertEqual(inspect(self.data)['invalid'],1)
    def test_invalid_export_shapes(self):
        for value in (None, [], {}, {'room':'test','messages':None}, {'room':'test','messages':[None]}, {'room':'test','messages':['bad']}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                inspect(value)
    def test_cli_exit_codes(self):
        import json, subprocess, sys, tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as folder:
            source, output = Path(folder)/'input.json', Path(folder)/'report.json'
            def run(data, strict=False):
                source.write_text(json.dumps(data))
                return subprocess.run([sys.executable, str(Path(__file__).with_name('receipts.py')), str(source), '--out', str(output)] + (['--strict'] if strict else []), capture_output=True)
            self.assertEqual(run(self.data).returncode, 0)
            altered=copy.deepcopy(self.data); altered['messages'][0]['text']='tampered'
            self.assertEqual(run(altered).returncode, 1)
            self.assertEqual(json.loads(output.read_text())['invalid'], 1)
            unsigned=copy.deepcopy(self.data); del unsigned['messages'][0]['sig']
            self.assertEqual(run(unsigned).returncode, 0)
            self.assertEqual(run(unsigned, True).returncode, 1)
            self.assertEqual(run({'room':'test','messages':[]}, True).returncode, 1)
            self.assertEqual(run([]).returncode, 2)
            before=source.read_bytes()
            result=subprocess.run([sys.executable,str(Path(__file__).with_name('receipts.py')),str(source),'--out',str(source)],capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(source.read_bytes(), before)
if __name__=='__main__':unittest.main()


