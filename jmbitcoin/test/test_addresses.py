from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import * # noqa: F401
import jmbitcoin as btc
import json
import pytest
import os
testdir = os.path.dirname(os.path.realpath(__file__))

def validate_address(addr, nettype):
    """A mock of jmclient.validate_address
    """
    BTC_P2PK_VBYTE = {"mainnet": b'\x00', "testnet": b'\x6f'}
    BTC_P2SH_VBYTE = {"mainnet": b'\x05', "testnet": b'\xc4'}    
    try:
        ver = btc.get_version_byte(addr)
    except AssertionError as e:
        return False, 'Checksum wrong. Typo in address?'
    except Exception as e:
        return False, "Invalid bitcoin address"
    if ver not in [BTC_P2PK_VBYTE[nettype], BTC_P2SH_VBYTE[nettype]]:
        return False, 'Wrong address version. Testnet/mainnet confused?'
    if len(btc.b58check_to_bin(addr)) != 20:
        return False, "Address has correct checksum but wrong length."
    return True, 'address validated'

@pytest.mark.parametrize(
    "net",
    [
        # 1
        ("mainnet"),
        # 2
        ("testnet")
    ])
def test_b58_invalid_addresses(net):
    #none of these are valid as any kind of key or address
    with open(os.path.join(testdir,"base58_keys_invalid.json"), "r") as f:
        json_data = f.read()
    invalid_key_list = json.loads(json_data)
    for k in invalid_key_list:
        bad_key = k[0]
        res, message = validate_address(bad_key, nettype=net)
        assert res == False, "Incorrectly validated address: " + bad_key + " with message: " + message

def test_b58_valid_addresses():
    with open(os.path.join(testdir,"base58_keys_valid.json"), "r") as f:
        json_data = f.read()
    valid_keys_list = json.loads(json_data)
    for a in valid_keys_list:
        addr, pubkey, prop_dict = a
        if not prop_dict["isPrivkey"]:
            if prop_dict["isTestnet"]:
                net = "testnet"
            else:
                net = "mainnet"
            #if using pytest -s ; sanity check to see what's actually being tested
            res, message = validate_address(addr, net)
            assert res == True, "Incorrectly failed to validate address: " + addr + " with message: " + message

