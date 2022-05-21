import json
from datetime import datetime
from socket import *

from conf import *
from conf_RSA import *


def user(hash_func):
    _document_ = {
        'CMSVersion': 1,
        'DigestAlgorithmIdentifiers': 'sha-256',
        'EncapsulatedContentInfo': {'ContentType': 'text',
                                    'OCTET STRING OPTIONAL': 'исходный текст',
                                    },
        'CertificateSet OPTIONAL': 'открытый ключ',
        'RevocationInfoChoises OPTIONAL': None,
        'SignerInfos': {
            'CMSVersion': 1,
            'SignerIdentifier': 'Nikich228rus',
            'DigestAlgorithmIdentifier': 'sha-256',
            'SignedAttributes OPTIONAL': None,
            'SignatureAlgorithmIdentifier': 'RSAdsi',
            'SignatureValue': 'h(m)^d1 mod n',
            'UnsignedAttributes OPTIONAL': {
                'OBJECT IDENTIFIER': 'signature-time-stamp',
                'SET OF AttributeValue': None
            }
        }
    }

    message = open('input.txt', 'r', encoding='utf-8').read()
    if hash_func == '1':
        message_hash = sha_256(message)
        _document_['DigestAlgorithmIdentifiers'] = 'sha-256'
    elif hash_func == '2':
        message_hash = sha_512(message)
        _document_['DigestAlgorithmIdentifiers'] = 'sha-512'

    else:
        raise ValueError
    key = 512
    generation_key(key)
    c = new_rsa_encryption(message_hash, 512)

    _private_key_ = json.load(open('file_PKCS12.json'))
    _public_key_ = json.load(open('file_PKCS8.json'))

    e = _public_key_['SubjectPublicKeyInfo']['publicExponent']
    n = _public_key_['SubjectPublicKeyInfo']['N']

    public_key = [e, n]

    _document_['EncapsulatedContentInfo']['OCTET STRING OPTIONAL'] = message.encode('utf-8').hex()
    _document_['CertificateSet OPTIONAL'] = public_key
    _document_['SignerInfos']['SignatureValue'] = c
    json.dump(_document_, open('PKCS_send.json', 'w+'))
    # print(message.encode('utf-8').hex())
    # print(bytes.fromhex(message.encode('utf-8').hex()).decode())


# user() --> centre() ---> user_after()


def decryption(text, key):
    d = key[0]
    n = key[1]
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


def centre_time():
    _document_ = json.load(open('PKCS_send.json', 'r'))

    message = bytes.fromhex(_document_['EncapsulatedContentInfo']['OCTET STRING OPTIONAL']).decode()
    message_hash = sha_256(message)

    c = _document_['SignerInfos']['SignatureValue']
    client_key = _document_['CertificateSet OPTIONAL']

    result_text = decryption(c, client_key)

    if message_hash == result_text:
        time_stamp = datetime.now()

        signature_message_hash = sha_256(message + c)

        key = 512
        generation_key(key)
        c = new_rsa_encryption(signature_message_hash + str(time_stamp), key)

        _private_key_ = json.load(open('file_PKCS12.json'))
        _public_key_ = json.load(open('file_PKCS8.json'))

        d = _private_key_['privateExponent']
        e = _public_key_['SubjectPublicKeyInfo']['publicExponent']
        n = _public_key_['SubjectPublicKeyInfo']['N']

        private_key = [d, n]
        public_key = [e, n]

        data_for_client = {
            'public key': public_key,
            'time_stamp': str(time_stamp),
            'Signature': c,
            'hash': signature_message_hash,
            'func': 'sha-256'
        }

        json.dump(data_for_client, open('PKCS_get.json', 'w+'))


def user_after():
    _data_ = json.load(open('PKCS_get.json', 'r'))
    _document_ = json.load(open('PKCS_send.json', 'r'))

    hash_func = _data_['func']
    c = _data_['Signature']
    centre_key = _data_['public key']
    time_stamp = _data_['time_stamp']

    message = bytes.fromhex(_document_['EncapsulatedContentInfo']['OCTET STRING OPTIONAL']).decode()
    Sn = _document_['SignerInfos']['SignatureValue']

    result = decryption(c, centre_key)
    result = result[:len(result) - len(time_stamp)]

    if hash_func == 'sha-256':
        hash_check = sha_256(message + Sn)
    elif hash_func == 'sha-512':
        hash_check = sha_512(message + Sn)
    else:
        raise ValueError

    if hash_check == result:
        _document_['SignerInfos']['UnsignedAttributes OPTIONAL']['SET OF AttributeValue'] = time_stamp
        json.dump(_document_, open('PKCS_send.json', 'w+'))


def client():


    client = socket(AF_INET, SOCK_STREAM)
    client.connect(('127.0.0.1', 2299))
    user()
    send_file = str(json.load(open('PKCS_send.json', 'r'))).encode()
    #send_file_list = [send_file[x: x + 1024] for x in range(0, len(send_file), 1024)]

    client.sendall(send_file)
    data_file = client.recv(4096)

    json.dump(eval(data_file), open('PKCS_get.json', 'w+'))
    client.close()

    user_after()


def client_send(file):
    client = socket(AF_INET, SOCK_STREAM)
    client.connect(('192.168.153.128', 2999))

    file_list = [file.encode()[x:x + 128] for x in range(0, len(file.encode()), 128)]
    for i in file_list:
        client.send(i)
        mess = client.recv(128)
        print(mess)

    client.send(b'END')

    data = b''
    while True:
        package = client.recv(128)

        if package != b'END':
            data = data + package
            client.send(b'OK')
        elif package == b'END':
            break

    json.dump(eval(data), open('PKCS_get.json', 'w+'))
    user_after()
    client.close()


if __name__ == '__main__':

    choose = input('hash func:\n1 - sha-256\n2 - sha-512\n>>>\t')
    if choose == '1':
        user('1')
        send_file = str(json.load(open('PKCS_send.json', 'r')))
        client_send(send_file)

    elif choose == '2':
        user('2')
        send_file = str(json.load(open('PKCS_send.json', 'r')))
        client_send(send_file)


