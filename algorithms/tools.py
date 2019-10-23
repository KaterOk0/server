import random
from flask import jsonify
from constants import *
from time import *


def getSessionKey(length):
    return ''.join(random.sample(chars, length))


def isKeyExpired(timeCreation):
    return time() - timeCreation > KEY_EXPIRATION_TIME


def returnValue(data=None, error=None):
    return jsonify(data=data, error=error)


def getInitVector(length):
    return ''.join(random.sample(chars, length))