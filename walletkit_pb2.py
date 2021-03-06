# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: walletkit.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import signer_pb2 as signer__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='walletkit.proto',
  package='walletrpc',
  syntax='proto3',
  serialized_options=_b('Z/github.com/lightningnetwork/lnd/lnrpc/walletrpc'),
  serialized_pb=_b('\n\x0fwalletkit.proto\x12\twalletrpc\x1a\x0csigner.proto\"6\n\x06KeyReq\x12\x18\n\x10key_finger_print\x18\x01 \x01(\x05\x12\x12\n\nkey_family\x18\x02 \x01(\x05\"\'\n\x14KeyForAddressRequest\x12\x0f\n\x07\x61\x64\x64r_in\x18\x01 \x01(\t\"\r\n\x0b\x41\x64\x64rRequest\"\x1c\n\x0c\x41\x64\x64rResponse\x12\x0c\n\x04\x61\x64\x64r\x18\x01 \x01(\t\"\x1d\n\x0bTransaction\x12\x0e\n\x06tx_hex\x18\x01 \x01(\x0c\"(\n\x0fPublishResponse\x12\x15\n\rpublish_error\x18\x01 \x01(\t\"I\n\x12SendOutputsRequest\x12\x12\n\nsat_per_kw\x18\x01 \x01(\x03\x12\x1f\n\x07outputs\x18\x02 \x03(\x0b\x32\x0e.signrpc.TxOut\"%\n\x13SendOutputsResponse\x12\x0e\n\x06raw_tx\x18\x01 \x01(\x0c\")\n\x12\x45stimateFeeRequest\x12\x13\n\x0b\x63onf_target\x18\x01 \x01(\x05\")\n\x13\x45stimateFeeResponse\x12\x12\n\nsat_per_kw\x18\x01 \x01(\x03\x32\xee\x03\n\tWalletKit\x12:\n\rDeriveNextKey\x12\x11.walletrpc.KeyReq\x1a\x16.signrpc.KeyDescriptor\x12\x38\n\tDeriveKey\x12\x13.signrpc.KeyLocator\x1a\x16.signrpc.KeyDescriptor\x12;\n\x08NextAddr\x12\x16.walletrpc.AddrRequest\x1a\x17.walletrpc.AddrResponse\x12H\n\rKeyForAddress\x12\x1f.walletrpc.KeyForAddressRequest\x1a\x16.signrpc.KeyDescriptor\x12H\n\x12PublishTransaction\x12\x16.walletrpc.Transaction\x1a\x1a.walletrpc.PublishResponse\x12L\n\x0bSendOutputs\x12\x1d.walletrpc.SendOutputsRequest\x1a\x1e.walletrpc.SendOutputsResponse\x12L\n\x0b\x45stimateFee\x12\x1d.walletrpc.EstimateFeeRequest\x1a\x1e.walletrpc.EstimateFeeResponseB1Z/github.com/lightningnetwork/lnd/lnrpc/walletrpcb\x06proto3')
  ,
  dependencies=[signer__pb2.DESCRIPTOR,])




_KEYREQ = _descriptor.Descriptor(
  name='KeyReq',
  full_name='walletrpc.KeyReq',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='key_finger_print', full_name='walletrpc.KeyReq.key_finger_print', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='key_family', full_name='walletrpc.KeyReq.key_family', index=1,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=44,
  serialized_end=98,
)


_KEYFORADDRESSREQUEST = _descriptor.Descriptor(
  name='KeyForAddressRequest',
  full_name='walletrpc.KeyForAddressRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='addr_in', full_name='walletrpc.KeyForAddressRequest.addr_in', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=100,
  serialized_end=139,
)


_ADDRREQUEST = _descriptor.Descriptor(
  name='AddrRequest',
  full_name='walletrpc.AddrRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=141,
  serialized_end=154,
)


_ADDRRESPONSE = _descriptor.Descriptor(
  name='AddrResponse',
  full_name='walletrpc.AddrResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='addr', full_name='walletrpc.AddrResponse.addr', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=156,
  serialized_end=184,
)


_TRANSACTION = _descriptor.Descriptor(
  name='Transaction',
  full_name='walletrpc.Transaction',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='tx_hex', full_name='walletrpc.Transaction.tx_hex', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=186,
  serialized_end=215,
)


_PUBLISHRESPONSE = _descriptor.Descriptor(
  name='PublishResponse',
  full_name='walletrpc.PublishResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='publish_error', full_name='walletrpc.PublishResponse.publish_error', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=217,
  serialized_end=257,
)


_SENDOUTPUTSREQUEST = _descriptor.Descriptor(
  name='SendOutputsRequest',
  full_name='walletrpc.SendOutputsRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='sat_per_kw', full_name='walletrpc.SendOutputsRequest.sat_per_kw', index=0,
      number=1, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='outputs', full_name='walletrpc.SendOutputsRequest.outputs', index=1,
      number=2, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=259,
  serialized_end=332,
)


_SENDOUTPUTSRESPONSE = _descriptor.Descriptor(
  name='SendOutputsResponse',
  full_name='walletrpc.SendOutputsResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='raw_tx', full_name='walletrpc.SendOutputsResponse.raw_tx', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=334,
  serialized_end=371,
)


_ESTIMATEFEEREQUEST = _descriptor.Descriptor(
  name='EstimateFeeRequest',
  full_name='walletrpc.EstimateFeeRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='conf_target', full_name='walletrpc.EstimateFeeRequest.conf_target', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=373,
  serialized_end=414,
)


_ESTIMATEFEERESPONSE = _descriptor.Descriptor(
  name='EstimateFeeResponse',
  full_name='walletrpc.EstimateFeeResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='sat_per_kw', full_name='walletrpc.EstimateFeeResponse.sat_per_kw', index=0,
      number=1, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=416,
  serialized_end=457,
)

_SENDOUTPUTSREQUEST.fields_by_name['outputs'].message_type = signer__pb2._TXOUT
DESCRIPTOR.message_types_by_name['KeyReq'] = _KEYREQ
DESCRIPTOR.message_types_by_name['KeyForAddressRequest'] = _KEYFORADDRESSREQUEST
DESCRIPTOR.message_types_by_name['AddrRequest'] = _ADDRREQUEST
DESCRIPTOR.message_types_by_name['AddrResponse'] = _ADDRRESPONSE
DESCRIPTOR.message_types_by_name['Transaction'] = _TRANSACTION
DESCRIPTOR.message_types_by_name['PublishResponse'] = _PUBLISHRESPONSE
DESCRIPTOR.message_types_by_name['SendOutputsRequest'] = _SENDOUTPUTSREQUEST
DESCRIPTOR.message_types_by_name['SendOutputsResponse'] = _SENDOUTPUTSRESPONSE
DESCRIPTOR.message_types_by_name['EstimateFeeRequest'] = _ESTIMATEFEEREQUEST
DESCRIPTOR.message_types_by_name['EstimateFeeResponse'] = _ESTIMATEFEERESPONSE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

KeyReq = _reflection.GeneratedProtocolMessageType('KeyReq', (_message.Message,), dict(
  DESCRIPTOR = _KEYREQ,
  __module__ = 'walletkit_pb2'
  # @@protoc_insertion_point(class_scope:walletrpc.KeyReq)
  ))
_sym_db.RegisterMessage(KeyReq)

KeyForAddressRequest = _reflection.GeneratedProtocolMessageType('KeyForAddressRequest', (_message.Message,), dict(
  DESCRIPTOR = _KEYFORADDRESSREQUEST,
  __module__ = 'walletkit_pb2'
  # @@protoc_insertion_point(class_scope:walletrpc.KeyForAddressRequest)
  ))
_sym_db.RegisterMessage(KeyForAddressRequest)

AddrRequest = _reflection.GeneratedProtocolMessageType('AddrRequest', (_message.Message,), dict(
  DESCRIPTOR = _ADDRREQUEST,
  __module__ = 'walletkit_pb2'
  # @@protoc_insertion_point(class_scope:walletrpc.AddrRequest)
  ))
_sym_db.RegisterMessage(AddrRequest)

AddrResponse = _reflection.GeneratedProtocolMessageType('AddrResponse', (_message.Message,), dict(
  DESCRIPTOR = _ADDRRESPONSE,
  __module__ = 'walletkit_pb2'
  # @@protoc_insertion_point(class_scope:walletrpc.AddrResponse)
  ))
_sym_db.RegisterMessage(AddrResponse)

Transaction = _reflection.GeneratedProtocolMessageType('Transaction', (_message.Message,), dict(
  DESCRIPTOR = _TRANSACTION,
  __module__ = 'walletkit_pb2'
  # @@protoc_insertion_point(class_scope:walletrpc.Transaction)
  ))
_sym_db.RegisterMessage(Transaction)

PublishResponse = _reflection.GeneratedProtocolMessageType('PublishResponse', (_message.Message,), dict(
  DESCRIPTOR = _PUBLISHRESPONSE,
  __module__ = 'walletkit_pb2'
  # @@protoc_insertion_point(class_scope:walletrpc.PublishResponse)
  ))
_sym_db.RegisterMessage(PublishResponse)

SendOutputsRequest = _reflection.GeneratedProtocolMessageType('SendOutputsRequest', (_message.Message,), dict(
  DESCRIPTOR = _SENDOUTPUTSREQUEST,
  __module__ = 'walletkit_pb2'
  # @@protoc_insertion_point(class_scope:walletrpc.SendOutputsRequest)
  ))
_sym_db.RegisterMessage(SendOutputsRequest)

SendOutputsResponse = _reflection.GeneratedProtocolMessageType('SendOutputsResponse', (_message.Message,), dict(
  DESCRIPTOR = _SENDOUTPUTSRESPONSE,
  __module__ = 'walletkit_pb2'
  # @@protoc_insertion_point(class_scope:walletrpc.SendOutputsResponse)
  ))
_sym_db.RegisterMessage(SendOutputsResponse)

EstimateFeeRequest = _reflection.GeneratedProtocolMessageType('EstimateFeeRequest', (_message.Message,), dict(
  DESCRIPTOR = _ESTIMATEFEEREQUEST,
  __module__ = 'walletkit_pb2'
  # @@protoc_insertion_point(class_scope:walletrpc.EstimateFeeRequest)
  ))
_sym_db.RegisterMessage(EstimateFeeRequest)

EstimateFeeResponse = _reflection.GeneratedProtocolMessageType('EstimateFeeResponse', (_message.Message,), dict(
  DESCRIPTOR = _ESTIMATEFEERESPONSE,
  __module__ = 'walletkit_pb2'
  # @@protoc_insertion_point(class_scope:walletrpc.EstimateFeeResponse)
  ))
_sym_db.RegisterMessage(EstimateFeeResponse)


DESCRIPTOR._options = None

_WALLETKIT = _descriptor.ServiceDescriptor(
  name='WalletKit',
  full_name='walletrpc.WalletKit',
  file=DESCRIPTOR,
  index=0,
  serialized_options=None,
  serialized_start=460,
  serialized_end=954,
  methods=[
  _descriptor.MethodDescriptor(
    name='DeriveNextKey',
    full_name='walletrpc.WalletKit.DeriveNextKey',
    index=0,
    containing_service=None,
    input_type=_KEYREQ,
    output_type=signer__pb2._KEYDESCRIPTOR,
    serialized_options=None,
  ),
  _descriptor.MethodDescriptor(
    name='DeriveKey',
    full_name='walletrpc.WalletKit.DeriveKey',
    index=1,
    containing_service=None,
    input_type=signer__pb2._KEYLOCATOR,
    output_type=signer__pb2._KEYDESCRIPTOR,
    serialized_options=None,
  ),
  _descriptor.MethodDescriptor(
    name='NextAddr',
    full_name='walletrpc.WalletKit.NextAddr',
    index=2,
    containing_service=None,
    input_type=_ADDRREQUEST,
    output_type=_ADDRRESPONSE,
    serialized_options=None,
  ),
  _descriptor.MethodDescriptor(
    name='KeyForAddress',
    full_name='walletrpc.WalletKit.KeyForAddress',
    index=3,
    containing_service=None,
    input_type=_KEYFORADDRESSREQUEST,
    output_type=signer__pb2._KEYDESCRIPTOR,
    serialized_options=None,
  ),
  _descriptor.MethodDescriptor(
    name='PublishTransaction',
    full_name='walletrpc.WalletKit.PublishTransaction',
    index=4,
    containing_service=None,
    input_type=_TRANSACTION,
    output_type=_PUBLISHRESPONSE,
    serialized_options=None,
  ),
  _descriptor.MethodDescriptor(
    name='SendOutputs',
    full_name='walletrpc.WalletKit.SendOutputs',
    index=5,
    containing_service=None,
    input_type=_SENDOUTPUTSREQUEST,
    output_type=_SENDOUTPUTSRESPONSE,
    serialized_options=None,
  ),
  _descriptor.MethodDescriptor(
    name='EstimateFee',
    full_name='walletrpc.WalletKit.EstimateFee',
    index=6,
    containing_service=None,
    input_type=_ESTIMATEFEEREQUEST,
    output_type=_ESTIMATEFEERESPONSE,
    serialized_options=None,
  ),
])
_sym_db.RegisterServiceDescriptor(_WALLETKIT)

DESCRIPTOR.services_by_name['WalletKit'] = _WALLETKIT

# @@protoc_insertion_point(module_scope)
