import os, binascii, hashlib, base58, ecdsa, blockcypher, time

class BitcoinAddress:

    def __init__(self):
        self.privateKey, self.publicKey = self.generate()

    def ripemd160(self, x):
        d = hashlib.new('ripemd160')
        d.update(x)
        return d
        
    def generate(self):

        # generate private key , uncompressed WIF starts with "5"
        priv_key = os.urandom(32)
        fullkey = '80' + binascii.hexlify(priv_key).decode()
        sha256a = hashlib.sha256(binascii.unhexlify(fullkey)).hexdigest()
        sha256b = hashlib.sha256(binascii.unhexlify(sha256a)).hexdigest()
        WIF = base58.b58encode(binascii.unhexlify(fullkey+sha256b[:8]))
        
        # get public key , uncompressed address starts with "1"
        sk = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        publ_key = '04' + binascii.hexlify(vk.to_string()).decode()
        hash160 = self.ripemd160(hashlib.sha256(binascii.unhexlify(publ_key)).digest()).digest()
        publ_addr_a = b"\x00" + hash160
        checksum = hashlib.sha256(hashlib.sha256(publ_addr_a).digest()).digest()[:4]
        publ_addr_b = base58.b58encode(publ_addr_a + checksum)
        return (WIF.decode(), publ_addr_b.decode())

counter = 0

while(True):
    addr = BitcoinAddress()
    try:
        balance = blockcypher.get_total_balance(addr.publicKey)
    except:
        print("API limitation exceeded")
    if(balance != 0):
        print(balance, addr.publicKey, addr.privateKey)
    if(counter % 1000 == 0):
        print('Queries: ', counter)
    counter += 1
    time.sleep(18) # wait 18 seconds --> 200 requests per hour, limit of blockcypher API