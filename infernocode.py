import base64
from Crypto.Cipher import AES
import json
import secretsharing as sss
from hashlib import sha256
import sys

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


# Straight from https://github.com/sftcd/cs7ns1/blob/master/assignments/practical5/as5-makeinferno.py
def pxor(pwd,share):
    words=share.split("-")
    hexshare=words[1]
    slen=len(hexshare)
    hashpwd=sha256(pwd).hexdigest()
    hlen=len(hashpwd)
    outlen=0
    if slen<hlen:
        outlen=slen
        hashpwd=hashpwd[0:outlen]
    elif slen>hlen:
        outlen=slen
        hashpwd=hashpwd.zfill(outlen)
    else:
        outlen=hlen
    xorvalue=int(hexshare, 16) ^ int(hashpwd, 16) # convert to integers and xor
    paddedresult='{:x}'.format(xorvalue)          # convert back to hex
    paddedresult=paddedresult.zfill(outlen)       # pad left
    result=words[0]+"-"+paddedresult              # put index back
    return result


# Modified from https://www.quickprogrammingtips.com/python/aes-256-encryption-and-decryption-in-python.html
def decrypt(enc, password):
    password = password.zfill(32).decode('hex')
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(password, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))



#1. Read in JSON
location = sys.argv[1]
f = open(location, "r")
data = json.load(f)
f.close()

ciphertext = data['ciphertext']
hashes = data['hashes']
shares = data['shares']


# 2. XOR the cracked passwords with their corresponding shares to create a list of
#    valid shares that could then be used to try to recover the key
xored = []
for h, s in zip(hashes, shares):
    splt = h.split(" ")
    if len(splt) > 1:
        password = " ".join(splt[:-1])
        xored.append(str(pxor(password, s)))

print ("\n[1/4] Read in {} chars of ciphertext and {} hashes, {} of which are cracked".format(len(ciphertext), len(hashes), len(xored)))


# 3. Use the XORed shares to generate the key
secret = sss.SecretSharer.recover_secret(xored)
print ("[2/4] The cracked passwords generated this key: {}".format(secret))


# 4. Use the generated key to attempt to decrypt the next level and do a quick check to see if we managed to decrypt it
print ("[3/4] Using the key to attempt to decrypt the next level...")
d = decrypt(ciphertext, secret)
success = False

try:
    j = json.loads(d)
    cipher = len(j["ciphertext"])
    hashes = len(j["hashes"])
    print ("      Looks like we unlocked the next level!")
    print ("      It has {} chars of ciphertext and {} hashes.".format(cipher, hashes))
    print ("      Here is the key that was used to unlock it: {}".format(secret))
    success = True
except Exception:
    print ("      We most likely don't have enough passwords cracked because what was decrypted doesn't look like a JSON")
    print ("      But still, have a look at the output file to be extra sure!")


# 5. Save the result of the decryption to a file
saveloc = location + ".unlocked.json"
f = open(saveloc, "wb")
f.write(d)
f.close()
print ("[4/4] Saved what was decrypted to {}".format(saveloc))

if success: print ("""

 .-----------------. .----------------.  .----------------.  .----------------. 
| .--------------. || .--------------. || .--------------. || .--------------. |
| | ____  _____  | || |     _____    | || |     ______   | || |  _________   | |
| ||_   \|_   _| | || |    |_   _|   | || |   .' ___  |  | || | |_   ___  |  | |
| |  |   \ | |   | || |      | |     | || |  / .'   \_|  | || |   | |_  \_|  | |
| |  | |\ \| |   | || |      | |     | || |  | |         | || |   |  _|  _   | |
| | _| |_\   |_  | || |     _| |_    | || |  \ `.___.'\  | || |  _| |___/ |  | |
| ||_____|\____| | || |    |_____|   | || |   `._____.'  | || | |_________|  | |
| |              | || |              | || |              | || |              | |
| '--------------' || '--------------' || '--------------' || '--------------' |
 '----------------'  '----------------'  '----------------'  '----------------' 

""")
