from time import *

from flask import Flask, request

from algorithms import *
from algorithms import aes
from tools import *

app = Flask(__name__)

users = {
    'admin': {'password': '1111', 'secret': '111', },
    'irina': {'password': '2222', 'secret': '222', },
    'katya': {'password': '3333', 'secret': '333', },
}

privateKey = ()


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user, password, userKey = data.get('user'), data.get('password'), data.get('userKey')
    userKey = gm.decrypt(privateKey, userKey)
    # user = bytes(aes.decrypt(user, userKey)).decode('utf-8', 'ignore')
    password = bytes(aes.decrypt(password, userKey)).decode('utf-8', 'ignore')
    try:
        if users.get(user, {}).get('password') != password:
            raise ValueError('Incorrect login or password!')
        publicKey = int(data['key']['x']), int(data['key']['n'])
        sessionKey = getSessionKey(KEY_LENGTH)
        encryptedKey = gm.encrypt(publicKey, sessionKey)
        users[user]['sessionKey'] = sessionKey
        users[user]['creationTime'] = time()

        print("I send encrypted sessionKey : ", encryptedKey)
        json = returnValue(data={'sessionKey': encryptedKey})
    except ValueError as error:
        json = returnValue(error=error)

    return json


@app.route('/file', methods=['POST'])
def getFile():
    data = request.get_json()
    user = users.get(data['user'], {})

    try:
        if not user.get('sessionKey') or isKeyExpired(user.get('creationTime')):
            raise ValueError('Required new session key. Session key has expired!')

        sessionKey = user['sessionKey']

        with open(os.path.join(APP_ROOT, 'notebook.txt'), 'r') as f:
            data = f.read()
            encrypted = aes.encrypt(data, sessionKey)
            print("I send encrypted text")
            json = returnValue(data={'encrypted': encrypted})
    except ValueError as error:
        print(error)
    return json

@app.route('/newFile', methods=['POST'])
def setFile():
    data = request.get_json()
    user = users.get(data['user'], {})
    try:
        secret = data.get('secret', '')
        sessionKey = user.get('sessionKey', '')
        if not sessionKey or isKeyExpired(user.get('creationTime')):
            raise ValueError('Required new session key. Session key has expired!')

        secret = aes.decrypt(secret, sessionKey)
        name = data.get('user', '')
        userKey = data.get('userKey')
        data = data.get('data')

        userKey = gm.decrypt(privateKey, userKey)
        # name = bytes(aes.decrypt(name, userKey)).decode('utf-8', 'ignore')
        if name not in users:
            raise ValueError('Incorrect name: %s !' % name)
        if bytes(secret).decode("utf-8", 'ignore') != users[name].get('secret'):
            print('Bad Eva')
            raise ValueError('Bad Eva!')

        with open(os.path.join(APP_ROOT, 'notebook.txt'), 'w') as f:
            decrypted = bytes(aes.decrypt(data, sessionKey)).decode('utf-8', 'ignore')
            f.write(decrypted)
        newSecret = getSessionKey(SECRET_LENGTH)
        print('I generate new secret ', newSecret)

        users[name]['secret'] = newSecret
        newSecret = aes.encrypt(newSecret, sessionKey)
        print('I send ney encrypted secret ', newSecret)
        json = returnValue(data={'secret': newSecret})
    except ValueError as error:
        json = returnValue(error=error)
    return json


@app.route('/private/gm/generate', methods=['POST'])
def getGmKeys():
    global privateKey
    data = request.get_json()
    try:
        p = int(data['p'])
        q = int(data['q'])
        if p > MAX_NUMBER or q > MAX_NUMBER:
            raise ValueError('Please, input numbers < 300!')
        if not (gm.isPrimeNumber(p) and gm.isPrimeNumber(q)):
            raise ValueError('Required prime numbers!')
        publicKey, privateKey = gm.generatePairKey(p, q)
        x, n = publicKey
        json = returnValue(data={'x': x, 'n': n})
    except ValueError as error:
        json = returnValue(error=str(error))
    return json


@app.route('/private/gm/decrypt', methods=['POST'])
def gmDecrypt():
    global privateKey
    data = request.get_json()
    try:
        data = data['data']
        decrypt = gm.decrypt(privateKey, data)
        print('use gmDecrypt, return ', decrypt)
        json = returnValue({'decrypted': decrypt})
    except ValueError:
        json = returnValue('Incorrect private key!')
    return json


@app.route('/private/cfb/decrypt', methods=['POST'])
def aesDecrypt():
    data = request.get_json()
    encrypted, sessionKey = data['encrypted'], data['key']
    decrypted = bytes(aes.decrypt(encrypted, sessionKey)).decode('utf-8', 'ignore')
    return returnValue({'text': decrypted})


@app.route('/private/cfb/encrypt', methods=['POST'])
def aesEncrypt():
    data = request.get_json()
    data, key = data['data'], data['key']
    encrypted = aes.encrypt(data, key)
    return returnValue({'text': encrypted})


@app.route('/private/userKey', methods=['POST'])
def getUserKey():
    data = request.get_json()
    key = int(data['key']['x']), int(data['key']['n'])
    userKey = getSessionKey(KEY_LENGTH)
    userKey = gm.encrypt(key, userKey)
    print('encryptUserKey : ', userKey)
    return returnValue({'userKey': userKey})


if __name__ == '__main__':
    app.run(host='192.168.0.106')
