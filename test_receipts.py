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
if __name__=='__main__':unittest.main()
