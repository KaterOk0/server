from flask import Flask, request, jsonify

from algorithms import aes
from tools import *
from algorithms import *
from time import *

app = Flask(__name__)

users = {
    'admin': {'password': '1111', },
    'irina': {'password': '2222', },
    'katya': {'password': '3333', },
}


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user, password = data.get('user'), data.get('password')

    try:
        if users.get(user, {}).get('password') != password:
            raise ValueError('Incorrect login or password!')
        publicKey = int(data['key']['x']), int(data['key']['n'])
        sessionKey = getSessionKey(KEY_LENGTH)
        encryptedKey = gm.encrypt(publicKey, sessionKey)

        if __debug__:
            print('SESSION_KEY:', session_key)

        users[user]['sessionKey'] = sessionKey
        users[user]['creationTime'] = time()

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

        with open(os.path.join(APP_ROOT, 'notebook.txt'), 'rb') as f:
            data = list(f.read())
            encrypted = aes.encrypt(data, sessionKey)
            if __debug__:
                decrypted = aes.decrypt(encrypted, sessionKey)
                print('ENCRYPTION CORRECT:', bytes(decrypted).startswith(bytes(data)))
            json = returnValue(data={'encrypted': encrypted})
    except ValueError as error:
        json = returnValue(error=error)
    return json


@app.route('/private/gm/generate', methods=['POST'])
def getGmKeys():
    data = request.get_json()
    try:
        p = int(data['p'])
        q = int(data['q'])
        if not (gm.isPrimeNumber(p) and gm.isPrimeNumber(q)):
            raise ValueError('Required prime numbers!')
        publicKey, privateKey = gm.generatePairKey(p, q)
        x, n = publicKey
        p, q = privateKey
        json = returnValue(data={'x': x, 'n': n, 'p': p, 'q': q})
    except ValueError as error:
        json = returnValue(error=str(error))
    return json


@app.route('/private/gm/decrypt', methods=['POST'])
def gmDecrypt():
    data = request.get_json()
    try:
        privateKey = int(data['key']['p']), int(data['key']['q'])
        data = data['data']
        json = returnValue({'decrypted': gm.decrypt(privateKey, data)})
    except ValueError:
        json = returnValue('Incorrect private key!')
    return json


@app.route('/private/cfb/decrypt', methods=['POST'])
def aesDecrypt():
    data = request.get_json()
    encrypted, sessionKey = data['encrypted'], data['key']
    decrypted = bytes(aes.decrypt(encrypted, sessionKey)).decode('utf-8', 'ignore')
    return returnValue({'text': decrypted})


if __name__ == '__main__':
    app.run(host='192.168.43.205')