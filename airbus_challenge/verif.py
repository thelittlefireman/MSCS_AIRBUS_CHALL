#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import argparse

try:
    from Crypto.PublicKey import RSA
    from Crypto.Hash import SHA256
    from Crypto.Signature import PKCS1_v1_5
except:
    print("pycrypto is missing")
    sys.exit(1)

SZ_STAMP=24


def parse_args():
    parser = argparse.ArgumentParser(description="Description of python program")
    parser.add_argument("--pub-key","-k",metavar="PUBLIC_KEY",help="Public Key to use")
    parser.add_argument("--cert","-c",metavar="CERTIFICATE",help="Certificate to verify")
    return parser.parse_args()


def check_sign(data,sign,key):
    h = SHA256.new()
    h.update(data)
    return PKCS1_v1_5.new(key).verify(h, sign)


def check_cert(cert,key):
    pos = cert.find(b"Secret Stamp :: ")
    if pos == -1: return False
    data_in,sign = cert[:pos+SZ_STAMP],cert[pos+SZ_STAMP:]
    return check_sign(data_in,sign,key)


def main():
    """ Entry Point Program """
    args = parse_args()

    try:
        cert = open(args.cert,"rb").read()
    except:
        print("Unable to open certificate")
        return 1

    try:
        key = RSA.importKey(open(args.pub_key,"rb").read())
    except:
        print("Unable to open public key")
        return 1

    if check_cert(cert,key):
        print("Access granted")
    else:
        print("Access denied")

    return 0


if __name__ == "__main__":
   sys.exit(main())
