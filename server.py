from flask import Flask, request, jsonify
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

    if users.get(user, {}).get('password') == password:
        try:
            publicKey = int(data['key']['q']), int(data['key']['p'])
            sessionKey = getSessionKey(KEY_LENGTH)
            encryptedKey = gm.encrypt(publicKey, sessionKey)

            if __debug__:
                print('SESSION_KEY:', session_key)

            users[user]['sessionKey'] = sessionKey
            users[user]['creationTime'] = time()

            json = returnValue(data={'sessionKey': encryptedKey})
        except ValueError:
            json = returnValue(error='Incorrect public key!')
    else:
        json = returnValue(error='Incorrect login or password!')
    return json


@app.route('/file', methods=['POST'])
def getFile():
    data = request.get_json()
    user = users.get(data['user'], {})

    if user.get('sessionKey') and not isKeyExpired(user.get('creationTime')):

        sessionKey = user['sessionKey']

        with open(os.path.join(APP_ROOT, 'notebook.txt'), 'rb') as f:
            data = list(f.read())
            encrypted = cfb.encrypt(data, sessionKey)
            if __debug__:
                decrypted = cfb.decrypt(encrypted, sessionKey)
                print('ENCRYPTION CORRECT:', bytes(decrypted).startswith(bytes(data)))
            json = returnValue(data={'encrypted': encryptedData})
    else:
        json = returnValue(error='Required new session key. Session key has expired!')
    return json


@app.route('/private/gm/generate', methods=['POST'])
def getGmKeys():
    data = request.get_json()
    try:
        publicKey, privateKey = gm.generatePairKey(int(data['p']), int(data['q']))
        e, n = publicKey
        d, n = privateKey
        json = returnValue(data={'e': e, 'd': d, 'n': n})
    except ValueError as error:
        json = returnValue(error=str(error))
    return json


@app.route('/private/gm/decrypt', methods=['POST'])
def gmDecrypt():
    data = request.get_json()
    try:
        privateKey = int(data['key']['d']), int(data['key']['n'])
        data = data['data']
        json = returnValue({'decrypted': gm.decrypt(privateKey, data)})
    except ValueError:
        json = returnValue('Incorrect private key!')
    return json


@app.route('/private/cfb/decrypt', methods=['POST'])
def cfbDecrypt():
    data = request.get_json()
    encrypted, sessionKey = data['encrypted'], data['key']
    decrypted = bytes(cfb.decrypt(encrypted, sessionKey)).decode('utf-8', 'ignore')
    return returnValue({'text': decrypted})


if __name__ == '__main__':
    app.run(host='192.168.0.106')