from .constants import *
from copy import copy


def unionData(state):
    output = [0x00 for _ in range(ROWS_NUM * COLS_NUM)]
    for i in range(ROWS_NUM):
        for j in range(COLS_NUM):
            output[i + ROWS_NUM * j] = state[i][j]
    return output


def mul02(num):
    res = (num << 1)
    if num >= 0x80:
        res ^= 0x1b
    return res % 0x100


def mul(byte2, byte1):
    if byte2 == 0x02:
        return mul02(byte1)
    elif byte2 == 0x03:
        return mul02(byte1) ^ byte1
    elif byte2 == 0x09:
        return mul02(mul02(mul02(byte1))) ^ byte1
    elif byte2 == 0x0b:
        return mul02(mul02(mul02(byte1))) ^ mul02(byte1) ^ byte1
    elif byte2 == 0x0d:
        return mul02(mul02(mul02(byte1))) ^ mul02(mul02(byte1)) ^ byte1
    elif byte2 == 0x0e:
        return mul02(mul02(mul02(byte1))) ^ mul02(mul02(byte1)) ^ mul02(byte1)


def addRoundKey(state, roundKey, roundNum=0):
    newState = state[:]
    for i in range(ROWS_NUM):
        newState[i] = [state[i][j] ^ roundKey[COLS_NUM * roundNum + i][j]
                       for j in range(COLS_NUM)]
    return newState


def mixColumns(state, isEncrypt=True):
    state = state[:]
    for i in range(ROWS_NUM):
        if isEncrypt:
            s0 = mul(0x02, state[0][i]) ^ mul(0x03, state[1][i]) ^ state[2][i] ^ state[3][i]
            s1 = state[0][i] ^ mul(0x02, state[1][i]) ^ mul(0x03, state[2][i]) ^ state[3][i]
            s2 = state[0][i] ^ state[1][i] ^ mul(0x02, state[2][i]) ^ mul(0x03, state[3][i])
            s3 = mul(0x03, state[0][i]) ^ state[1][i] ^ state[2][i] ^ mul(0x02, state[3][i])
        else:
            s0 = mul(0x0e, state[0][i]) ^ mul(0x0b, state[1][i]) ^ mul(0x0d, state[2][i]) ^ mul(0x09, state[3][i])
            s1 = mul(0x09, state[0][i]) ^ mul(0x0e, state[1][i]) ^ mul(0x0b, state[2][i]) ^ mul(0x0d, state[3][i])
            s2 = mul(0x0d, state[0][i]) ^ mul(0x09, state[1][i]) ^ mul(0x0e, state[2][i]) ^ mul(0x0b, state[3][i])
            s3 = mul(0x0b, state[0][i]) ^ mul(0x0d, state[1][i]) ^ mul(0x09, state[2][i]) ^ mul(0x0e, state[3][i])

        state[0][i] = s0
        state[1][i] = s1
        state[2][i] = s2
        state[3][i] = s3
    return state


def shiftRows(state, isEncrypt=True):
    state = state[:]
    sign = -1 if not isEncrypt else 1
    for idx in range(0, ROWS_NUM):
        state[idx] = state[idx][sign * idx:] + state[idx][:sign * idx]
    return state


def getPositionSBOX(b):
    return b // 0x10, b % 0x10


def subWord(word, box):
    idxRow, idxCol = getPositionSBOX(word)
    return box[SBOX_ROW * idxRow + idxCol]


def subBytes(state, isEncrypt=True):
    state = state[:]
    box = INV_SBOX if not isEncrypt else SBOX
    for i, s in enumerate(state):
        state[i] = [subWord(b, box) for b in s]
    return state


def generateRoundKey(key):
    byteKey = [ord(char) for char in key]
    roundKey = [[byteKey[i + ROWS_NUM * j] for j in range(COLS_NUM)] for i in range(ROWS_NUM)]

    for i in range(ROWS_NUM, COLS_NUM * (ROUNDS_NUM + 1)):
        temp = roundKey[i-1][:]

        if i % ROWS_NUM == 0:
            temp = roundKey[i - 1][1:] + roundKey[i - 1][:1]

            for j in range(ROWS_NUM):
                temp[j] = subWord(temp[j], SBOX) ^ (RCON[int(i / ROWS_NUM - 1)][j])

        for j in range(ROWS_NUM):
            temp[j] = (temp[j]) ^ (roundKey[i - ROWS_NUM][j])

        roundKey.append(temp)

    return roundKey


def aesCipher(data, key, isEncrypt=True):
    if len(key) != KEY_LENGTH:
        raise ValueError('Key should be length {}!'.format(KEY_LENGTH))
    roundKey = generateRoundKey(key)
    output = []
    c = [ord(ch) for ch in INIT_VECTOR]
    for i in range(0, len(data), KEY_LENGTH):
        c = encryptedBlock(c, roundKey)
        block = data[i:i + KEY_LENGTH]
        if len(block) < KEY_LENGTH:
            block.extend([0] * (KEY_LENGTH - len(block)))
        text = cfb(c, block)
        if isEncrypt:
            c = text
        else:
            c = block
        output.extend(text)
    return output


def encrypt(data, key):
    return aesCipher(bytearray(data.encode('utf-8')), key)


def encryptedBlock(block, roundKey):
    state = [[block[i + ROWS_NUM * j] for j in range(COLS_NUM)] for i in range(ROWS_NUM)]
    state = addRoundKey(state, roundKey)

    for roundNum in range(1, ROUNDS_NUM):
        state = addRoundKey(mixColumns(shiftRows(subBytes(state))), roundKey, roundNum)
    state = addRoundKey(shiftRows(subBytes(state)), roundKey, ROUNDS_NUM)
    return unionData(state)


def decrypt(data, key):
    b = aesCipher(data, key, False)
    for id in range(len(b)-1, 0, -1):
        if b[id] == 0:
            b.pop()
        else:
            break
    return b


# def decryptedBlock(block, roundKey):
#     state = [[block[i + ROWS_NUM * j] for j in range(COLS_NUM)] for i in range(ROWS_NUM)]
#     state = addRoundKey(state, roundKey, ROUNDS_NUM)
#     for roundNum in range(ROUNDS_NUM - 1, 0, -1):
#         state = mixColumns(addRoundKey(subBytes(shiftRows(state, True), True),
#                                        roundKey, roundNum), True)
#     state = addRoundKey(subBytes(shiftRows(state, True), True), roundKey, 0)
#     return unionData(state)


def cfb(block2, block1):
    # просто xor по двум битовым строкам
    res = copy(block2)
    for i in range(ROWS_NUM * COLS_NUM):
        res[i] ^= block1[i]
    return res
