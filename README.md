# lndwallettools
Tools to manipulate the on chain lnd wallet over grpc

Please note this is a **proof of concept** - it doesn't currently do anything useful
except demonstrate how it is possible to sign transactions out of the lnd wallet.
Developers may find it useful as a source of info on how to do this (and indeed how
to access lnd functionality over grpc generally).

## Installation

(Obviously much of this can be packaged up in future if it's ever considered useful)

First we follow a modified version of the instructions [here](https://dev.lightning.community/guides/python-grpc/):

1. clone this repo somewhere
2. `virtualenv lnwt` (or replace `lnwt` with anything that suits) (use `-p python3` option to virtualenv to specify Python3, if necessary).
3. `source lnwt/bin/activate`
4. `(lnwt)$ pip install grpcio grpcio-tools googleapis-common-protos`
5. `(lnwt)$ git clone https://github.com/googleapis/googleapis.git`

**Note**: we do not follow the next step in the above link; we don't need the `rpc.proto` as we already have the proto files here, and they are specific to a custom lnd version (see next).

Next, we need a custom install of lnd.
Note that this will be PR-ed to the lnd project and if merged, will obviate the need for this whole section:

First, I assume you have lnd installed, as this tool would be pointless otherwise. Go to the root of your lnd install.

1. `(lnwt)$ git remote add AdamISZ https://github.com/AdamISZ/lnd`
2. `(lnwt)$ git fetch AdamISZ signrpc-expt`
3. `(lnwt)$ git checkout signrpc-expt`
3. `(lnwt)$ tags="signrpc walletrpc" make install`

You will now have new builds of `lncli` and `lnd`. These won't affect normal operations; but you must restart the lnd daemon to continue.

Finally, we should install the `jmbitcoin` package (included here in the repo, for convenience) to do bitcoin operations.

1. `(lnwt)$ cd jmbitcoin`
2. `(lnwt)$ pip install -e .`

This will download a couple of dependencies and at this point you are ready to run the script.

## Running the script `lnd-wallet-tool.py`

* Transactions created will be displayed but not broadcast (see the commented out lines at the end of the script).
* This currently does only one rudimentary operation: takes your most recent two in-wallet utxos and signs a consolidation transaction,
sending the coins to a new address in the wallet.
* This **only** works with bech32 addresses (TODO: make it work with p2sh wrapped coins).
* Obviously this is mostly for education at this point; in future it can be extended, most interestingly to support coinjoins.

Usage: since it's just a toy script right now, it doesn't yet have any options; just do:

`(lnwt)$ python lnd-wallet-tool.py`


