import bitarray
from math import ceil, sqrt, gcd
from random import choice, randint
from .constants import MAX_X, MAX_ITER, MAX_RANDOM


def isQuadraticResidue(x, p):
    mod = 1
    for _ in range((p-1)//2):
        mod = (mod * x) % p
    return mod == 1


def isPrimeNumber(x):
    for i in range(2, x - 1):
        if x % i == 0:
            return False
    return True


def getNotQuadraticResidue(p, q):
    x = []
    for i in range(min(p, q)):
        if not isQuadraticResidue(i, p) and not isQuadraticResidue(i, q):
            x.append(i)
    if not x:
        return None
    return choice(x)


def generatePairKey(p, q):
    n = p * q
    x = getNotQuadraticResidue(p, q)
    if x is None:
        raise ValueError('Not exist private keys!')
    return (x, n), (p, q)


def encrypt(publicKey, text):
    x, n = publicKey
    input = bitarray.bitarray()
    input.frombytes(text.encode('utf-8'))
    y = []
    for _ in input:
        for _ in range(MAX_ITER):
            yi = randint(3, MAX_RANDOM)
            if gcd(yi, n) == 1:
                y.append(yi)
                break
    output = [(yi**2 * x**b) % n for yi, b in zip(y, input)]
    return output


def decrypt(privateKey, encrypted):
    p, q = privateKey
    ba = bitarray.bitarray()
    for c in encrypted:
        if isQuadraticResidue(c, p) and isQuadraticResidue(c, q):
            ba.append(0)
        else:
            ba.append(1)
    decoded = [chr(b) for b in ba.tobytes()]
    return ''.join(decoded)

