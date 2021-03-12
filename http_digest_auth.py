"""
Using HTTP digest authentication header information
See if password guess matches
"""

import hashlib
import sys


def get_md5(mystr):
    return hashlib.md5(mystr.encode()).hexdigest()


def get_digest_dict_from_string(header_string):
    digest_auth_items = (x.strip() for x in header_string.split(", "))
    split_equals = (x.split("=") for x in digest_auth_items)
    stripped_quotes = ((x[0], x[1].strip('"')) for x in split_equals)
    digest_dict = dict(stripped_quotes)
    return digest_dict


def is_password(digest_dict, method, password_guess):
    method = method.strip().upper()
    assert method in ("GET", "POST"), "Invalid method"
    
    HA1 = get_md5(":".join([digest_dict["username"], digest_dict["realm"], password_guess]))

    HA2 = get_md5(":".join([method, digest_dict["uri"]]))

    calculated_response = get_md5(":".join([HA1, digest_dict["nonce"], digest_dict["nc"],  digest_dict["cnonce"], digest_dict["qop"], HA2]))
    return calculated_response == digest_dict["response"]



def main():
    mystr = 'username="fmeyer", realm="PeakHMI", nonce="N6l8J53940BWi/157IWaddI06/ZULzyP", uri="/", response="e84d8e1c7e3506b2d9ebdbe42068919d", opaque="JvnGjaphFchhqB1MDFM7nT1FdpqSANZM6f", cnonce="0666a9f219af1e86d488531fc67d5d66", nc=00000001, qop="auth"'
    method = "GET"
    
    digest_dict = get_digest_dict_from_string(mystr)
    
    if len(sys.argv) < 2:
        print("Usage: {} <password_guess>".format(sys.argv[0]))
        exit()
    
    password_guess = sys.argv[1]
    
    if is_password(digest_dict, method, password_guess):
        print("Found password:", password_guess)
    else:
        print("Invalid password:", password_guess)

if __name__ == "__main__":
    main()