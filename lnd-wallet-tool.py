#!/usr/bin/env python

import rpc_pb2 as ln
import rpc_pb2_grpc as lnrpc
import signer_pb2 as signer
import signer_pb2_grpc as signrpc
import walletkit_pb2 as walletkit
import walletkit_pb2_grpc as walletrpc
import grpc
import os
from binascii import hexlify, unhexlify
from decimal import Decimal
import codecs

#for transaction creation and verification:
import jmbitcoin as btc

"""
The purpose of this script is to test the workflow of creating, signing and
broadcasting a custom transaction (for example coin control, selecting utxos,
or coinjoin, using other coins fed in from external sources)
using lnd's wallet, and the grpc subservers, specifically the walletkit and
signrpc subservers.

Boilerplate connection-setup code is taken from:
https://dev.lightning.community/guides/python-grpc/
(as well as instructions on how to setup the necessary Python venv)
"""

# for switching your testing mainnet/testnet/simnet
bitcoin_net = "mainnet"
# sighash_all byte for signatures
sighash_all_bytes = bytes([btc.SIGHASH_ALL])
# fee in satoshis considered unacceptable
absurd_fee = 200000

def get_secure_channel():
    # Due to updated ECDSA generated tls.cert we need to let gprc know that
    # we need to use that cipher suite otherwise there will be a handshake
    # error when we communicate with the lnd rpc server.
    os.environ["GRPC_SSL_CIPHER_SUITES"] = 'HIGH+ECDSA'    
    # Lnd cert is at ~/.lnd/tls.cert on Linux and
    # ~/Library/Application Support/Lnd/tls.cert on Mac
    cert = open(os.path.expanduser('~/.lnd/tls.cert'), 'rb').read()
    creds = grpc.ssl_channel_credentials(cert)
    # lnd's default grpc port is 10009
    return grpc.secure_channel('localhost:10009', creds)

def get_macaroons(requested):
    """
    Pass a list of strings which are names of macaroons
    to be extracted from the local lnd user directories.
    Returned are the macaroons (as hex-encoded data).
    """

    macaroons = []

    # Auth is enabled using macaroon files,
    # which are housed in lnd's user directories
    # (Note, Mac is different: # ~/Library/Application Support/Lnd/data/chain/bitcoin/...')
    macaroon_root = os.path.expanduser('~/.lnd/data/chain/bitcoin/' + bitcoin_net)

    for req in requested:
        macaroon_name = req + ".macaroon"
        with open(os.path.join(macaroon_root, macaroon_name), 'rb') as f:
            macaroon_bytes = f.read()
            macaroons.append(codecs.encode(macaroon_bytes, 'hex'))

    return macaroons

def get_our_coins(stub, macaroon):
    """Given a stub for connecting to the Lightning grpc,
    decide on which coins from the lnd wallet to use as input to the
    transaction we are creating.
    The return value is a list of dicts, one per coin, with at least
    one key "utxo", which will hold the grpc response Utxo message.
    This code is just a simple example, choosing the two most recently
    confirmed utxos.
    """
    # Select the two most recent coins:
    response = stub.ListUnspent(ln.ListUnspentRequest(
        min_confs=0, max_confs=100000), metadata=[('macaroon', macaroon)])
    # The output from ListUnspent is by default ordered with most recent
    # (smallest confs) first; this is what we want, if you want something
    # different, sort the list response.utxos by a value in the dict
    # (like 'amount_sat' e.g.)
    if len(response.utxos) < 2:
        raise Exception("We cannot build a 2 input transaction since "
                        "less than 2 coins are available")

    # Technical note: we cannot add attributes to the protocol message
    # objects, hence this custom dict to which we can add other items.
    return [{"utxo": x} for x in response.utxos[:2]]

def get_other_coins():
    """ In future this could be implemented to get other inputs
    to the transaction (which will require additional functions
    to get signatures, of course).
    """
    return []

def estimate_tx_fee(ins, outs, txtype, conftarget, stub, macaroon):
    """ Given a number of tx inputs, a number of txoutputs, a
    transaction type (one of "p2pkh", "p2sh-p2wpkh", "p2wpkh",
    but currently only the last is supported),
    a targeted number of confirmations, a stub and macaroon for lnd
    grpc connection to the Lightning service, returns an estimated
    fee in total satoshis, and an estimated tx size in form (
    witness bytes, non-witness bytes).
    TODO Note that all ins/outs are assumed to be the same type.
    """
    witness_est, nonwitness_est = btc.estimate_tx_size(
        ins, outs, txtype=txtype)

    # unfortunately, the rpc call *requires* a destination and amount
    # in order to estimate an overall fee for the transaction based
    # on what's in its wallet, even though we only want the fee *rate*
    # sourced from the blockchain. Here we just give it a dummy
    # destination and amount, because we don't actually care what its
    # overall fee estimate for the transaction is.
    dummy_addr = btc.pubkey_to_p2wpkh_address(btc.privkey_to_pubkey(
        bytes([1]*33), False))
    dummy_amt = 300000 # will fail if the wallet can't fund that
    fee_req = ln.EstimateFeeRequest(AddrToAmount={dummy_addr: dummy_amt},
                                    target_conf=conftarget)
    response = stub.EstimateFee(fee_req,
                                metadata=[('macaroon', macaroon)])
    fee_per_kb = response.feerate_sat_per_byte
    fee_est = int((nonwitness_est + 0.25*witness_est)*fee_per_kb)
    if fee_est > absurd_fee:
        raise Exception("Unacceptable fee estimated: ", fee_est,
                        " satoshis.")
    return fee_est

def main():

    # sets up grpc connection to lnd
    channel = get_secure_channel()

    # note that the 'admin' macaroon already has the required
    # permissions for the walletkit request, so we don't need
    # that third macaroon.
    macaroon, signer_macaroon = get_macaroons(["admin", "signer"])
    
    # the main stub allows access to the default rpc commands:
    stub = lnrpc.LightningStub(channel)
    # the signer stub allows us to access the rpc for signing
    # transactions on our coins:
    stub_signer = signrpc.SignerStub(channel)
    # we also need a stub for the walletkit rpc to extract
    # public keys for addresses holding coins:
    stub_walletkit = walletrpc.WalletKitStub(channel)
    
    # Here we start the process to sign a custom tx.
    # 1. List unspent coins, get most recent ones (just an example).
    # 2. Get the pubkeys of those addresses.
    # 3. Get the next unused address in the wallet as destination.
    # 4. Build a transaction, (in future: optionally taking extra
    #    inputs and outputs from elsewhere).
    # 5. Use signOutputRaw rpc to sign the new transaction.
    # 6. Use the walletkit PublishTransaction to publish.
    
    # Just an example of retrieving basic info, not necessary:
    # Retrieve and display the wallet balance
    response = stub.WalletBalance(ln.WalletBalanceRequest(),
                                  metadata=[('macaroon', macaroon)])
    print("Current on-chain wallet balance: ", response.total_balance)

    inputs = get_our_coins(stub, macaroon) + get_other_coins()

    for inp in inputs:
        # Attach auxiliary data needed to the inputs, for signing.

        # Get the public key of an address
        inp["pubkey"] = stub_walletkit.KeyForAddress(
            walletkit.KeyForAddressRequest(
            addr_in=inp["utxo"].address),
            metadata=[('macaroon', macaroon)]).raw_key_bytes

        # this data (known as scriptCode in BIP143 parlance)
        # is the pubkeyhash script for this p2wpkh, as is needed
        # to construct the signature hash.
        # **NOTE** This code currently works with bech32 only.
        # TODO update to allow p2sh-p2wpkh in wallet coins, also.
        inp["script"] = btc.pubkey_to_p2pkh_script(inp["pubkey"])
    
    
    # We need an output address for the transaction, this is taken from the
    # standard wallet 'new address' request (type 0 is bech32 p2wpkh):
    request = ln.NewAddressRequest(type=0,)
    response = stub.NewAddress(request, metadata=[('macaroon', macaroon)])
    output_address = response.address
    print("Generated new address: ", output_address)
    
    # Build the raw unsigned transaction
    tx_ins = []
    output_amt = 0
    for inp in inputs:
        tx_ins.append(inp["utxo"].outpoint.txid_str + ":" + str(
            inp["utxo"].outpoint.output_index))
        output_amt += inp["utxo"].amount_sat

    fee_est = estimate_tx_fee(2, 1, "p2wpkh", 6, stub, macaroon)

    output = {"address": output_address, "value": output_amt - fee_est}
    tx_unsigned = btc.mktx(tx_ins, [output], version=2)
    print(btc.deserialize(tx_unsigned))
    
    
    # use SignOutputRaw to sign each input (currently, they are all ours).
    raw_sigs = {}
    for i, inp in enumerate(inputs):
        # KeyDescriptors must contain at least one of the pubkey and the HD path,
        # here we use the latter:
        kd = signer.KeyDescriptor(raw_key_bytes=inp["pubkey"])
        # specify the utxo information for this input into a TxOut:
        sdout = signer.TxOut(value=inp["utxo"].amount_sat,
                             pk_script=unhexlify(inp["utxo"].pk_script))
        # we must pass a list of SignDescriptors; we could batch all into
        # one grpc call if we preferred. The witnessscript field is
        # constructed above as the "script" field in the input dict.
        sds = [signer.SignDescriptor(key_desc=kd, input_index=i,
                output=sdout, witness_script = inp["script"], sighash=1)]
        req = signer.SignReq(raw_tx_bytes=unhexlify(tx_unsigned),
                             sign_descs= sds)
        # here we make the actual signing request to lnd over grpc:
        response = stub_signer.SignOutputRaw(req,
                                metadata=[('macaroon', signer_macaroon)])
        # note that btcwallet's sign function does not return the sighash byte,
        # it must be added manually:
        raw_sigs[i] = response.raw_sigs[0] + sighash_all_bytes
    
    # insert the signatures into the relevant inputs in the deserialized tx
    tx_unsigned_deser = btc.deserialize(tx_unsigned)
    for i in range(len(inputs)):
        tx_unsigned_deser["ins"][i]["txinwitness"] = [btc.safe_hexlify(
            raw_sigs[i]), btc.safe_hexlify(inputs[i]["pubkey"])]
    print("Signed transaction: \n", tx_unsigned_deser)
    hextx = btc.serialize(tx_unsigned_deser)
    print("Serialized: ", hextx)
    print("You can broadcast this externally e.g. via Bitcoin Core")

    # TODO: uncomment to call to PublishTransaction for automatic brdcst:

    #proto_tx = walletkit.Transaction(tx_hex=hextx)
    #response = stub_walletkit.PublishTransaction(
    #    proto_tx, metadata=[('macaroon', macaroon)])
    #print("Publication response: ", response.publish_error)

if __name__ == "__main__":
    main()
    print("Finished OK")
