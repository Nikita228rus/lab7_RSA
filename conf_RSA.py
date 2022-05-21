import random
import math
import json


def euclid_algorithm(a, b, flag):
    r = [a, b]
    x = [1, 0]
    y = [0, 1]

    i = 0
    while r[i] != 0:
        if r[i + 1] != 0:

            q = (r[i] // r[i + 1])
            c = r[i] - q * r[i + 1]
            a = x[i] - q * x[i + 1]
            b = y[i] - q * y[i + 1]

            x.append(a)
            y.append(b)
            r.append(c)
            i += 1

        elif r[i + 1] == 0:
            break

    d = r[i]
    u = x[i]
    v = y[i]

    if flag is True:

        choose = input("1 - линейное представление НОД.\n2 - НОД.\n")
        if choose == "1":
            return f"{d} = {r[0]} * {u} + {r[1]} * {v}"
        elif choose == "2":
            return f"НОД{r[0], r[1]} = {d}"
        elif choose != "1" and choose != "2":
            return "Exit."

    elif flag is False:
        return [d, u, v]


def test_miller2(n):
    a = random.randint(1, n - 2)
    exp = n - 1
    while not exp & 1:
        exp >>= 1

    if pow(a, exp, n) == 1:
        return True

    while exp < n - 1:
        if pow(a, exp, n) == n - 1:
            return True
        exp <<= 1

    return False


def generation_prime(k):
    binary = []
    for i in range(k):
        bit = random.randint(0, 1)
        binary.append(bit)

    del binary[-1]
    binary.append(1)
    del binary[0]
    binary.insert(0, 1)

    p = int(''.join(str(x) for x in binary), 2)

    test = []
    for i in range(5):
        test.append(test_miller2(p))

    if test.count(True) == len(test):

        return p

    else:
        return generation_prime(k)


def func_rsa_generation(size):
    p = generation_prime(size)
    q = generation_prime(size)
    n = q * p
    func_euler = (p - 1) * (q - 1)
    e = random.randint(3, func_euler - 1)

    d = euclid_algorithm(e, func_euler, False)[1]
    while euclid_algorithm(e, func_euler, False)[0] != 1:
        e = random.randint(3, func_euler - 1)
        d = euclid_algorithm(e, func_euler, False)[1]
    while d < 0:
        d += func_euler

    coefficient = euclid_algorithm(q, p, False)[1]

    return [n, e, d, p, q, pow(d, 1, p - 1), pow(d, 1, q - 1), coefficient]


def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')


def int_to_bytes2(x):
    return x.to_bytes(math.ceil(math.log2(x) / 8), byteorder="big")


def text_to_int(text: str) -> int:
    return int.from_bytes(text.encode('utf-8'), 'big')


def text_to_bin(text):
    return ''.join(format(x, '08b') for x in bytearray(text, 'utf-8'))


def bin_to_text(text):
    temp_list = []
    var = None
    for i in range(len(text)):
        if i % 8 == 0:
            var = int(text[i:i + 8], 2)
            var = hex(var)[2:].zfill(2)
            temp_list.append(var)
    result = b''
    for i in temp_list:
        print(i)
        result += bytes.fromhex(i)
    return result.decode()
    # return bytes.fromhex(hex(int(text, 2))[2:]).decode()


def new_rsa_encryption(message, size_key):
    _data_ = {'EncryptedContentInfo': {'ContentType': 'text',
                                       'ContentEncryptionAlgorithmIdentifier': 'rsaEncryption',
                                       'encryptedContent': None,
                                       'OPTIONAL': None}}

    _private_key_ = json.load(open('file_PKCS12.json'))

    bytes_message = message.encode('utf-8')

    k = int(((size_key / 2) - 8) / 8)
    k2 = int(((size_key / 2) - 16) / 8)

    blocks_message = [bytes_message[x:x + k2] for x in range(0, len(bytes_message), k2)]

    if len(blocks_message[-1]) != k:
        l_var = len(blocks_message[-1])
        temp_var = (k - l_var) % k

        bytes_temp_var = int_to_bytes(temp_var)
        for i in range(temp_var):
            blocks_message[-1] = blocks_message[-1] + bytes_temp_var

        for i in range(len(blocks_message) - 1):
            blocks_message[i] = blocks_message[i] + bytes_temp_var

    e = _private_key_['privateExponent']
    n = _private_key_['prime1'] * _private_key_['prime2']
    for i in range(len(blocks_message)):
        blocks_message[i] = pow(int.from_bytes(blocks_message[i], 'big'), e, n)

    encrypted_content = ''
    for i in blocks_message:
        encrypted_content = encrypted_content + hex(i)[2:].zfill((k + 1) * 8)

    _data_['EncryptedContentInfo']['encryptedContent'] = encrypted_content

    json.dump(_data_, open('file_PKCS7.json', 'w+'))

    return encrypted_content


def rsa_decryption():
    _message_struc_ = json.load(open('file_PKCS7.json'))
    _public_key_ = json.load(open('file_PKCS8.json'))

    text = _message_struc_["EncryptedContentInfo"]["encryptedContent"]
    d = _public_key_['SubjectPublicKeyInfo']['publicExponent']
    n = _public_key_['SubjectPublicKeyInfo']['N']
    block = int(len(n) / 4)
    n = int(n, 2)
    c = [text[x:x + block] for x in range(0, len(text), block)]

    m = [None] * len(c)
    for i in range(len(c)):
        m[i] = int_to_bytes(pow(int(c[i], 16), d, n))

    temp_var = m[0][-1]

    for i in range(len(m) - 1):
        m[i] = m[i][:len(m[i]) - 1]

    for i in range(temp_var):
        m[-1] = m[-1][:len(m[-1]) - 1]
    result = b''.join(m).decode('utf-8')

    return result


def generation_key(size):

    _public_key_ = {'SubjectPublicKeyInfo': {
        'publicExponent': None,
        'N': None
    }}

    _private_key_ = {'privateExponent': None,
                     'prime1': None,
                     'prime2': None,
                     'exponent1': None,
                     'exponent2': None,
                     'coefficient': None,
                     }

    key = func_rsa_generation(size)

    key[0] = bin(key[0])[2:].zfill(size * 2)

    _public_key_['SubjectPublicKeyInfo']['publicExponent'] = key[1]
    _public_key_['SubjectPublicKeyInfo']['N'] = key[0]
    _private_key_['privateExponent'] = key[2]
    _private_key_['prime1'] = key[3]
    _private_key_['prime2'] = key[4]
    _private_key_['exponent1'] = key[5]
    _private_key_['exponent2'] = key[6]
    _private_key_['coefficient'] = key[7]

    json.dump(_public_key_, open('file_PKCS8.json', 'w+'))
    json.dump(_private_key_, open('file_PKCS12.json', 'w+'))

