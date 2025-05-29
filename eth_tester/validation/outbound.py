from typing import (
    Optional,
)

from eth_utils import (
    is_canonical_address,
    is_hexstr,
    is_list_like,
)
from eth_utils.toolz import (
    compose,
    merge,
    partial,
)
from toolz import (
    identity,
)

from eth_tester.constants import (
    UINT256_MAX,
    UINT2048_MAX,
)
from eth_tester.exceptions import (
    ValidationError,
)

from ..backends.pyevm.utils import (
    is_cancun_block,
    is_london_block,
    is_shanghai_block,
)
from .common import (
    if_not_create_address,
    if_not_null,
    validate_any,
    validate_array,
    validate_bytes,
    validate_dict,
    validate_positive_integer,
    validate_transaction_type,
)


def validate_hexstr(value, length: Optional[int] = None):
    if not is_hexstr(value):
        raise ValidationError(f"Value must be a hex string.  Got type: {type(value)}")
    if length and len(value) != length:
        # 0x + 32 bytes (64 hex chars)
        raise ValidationError(
            "Must be 32 byte hash represented as 0x-prefixed hex string of length 66.  "
            f"Got: `{value}` of length `{len(value)}`"
        )


validate_32_byte_hexstr = partial(validate_hexstr, length=66)
validate_20_byte_hexstr = partial(validate_hexstr, length=42)


def validate_nonce(value):
    validate_bytes(value)
    if len(value) != 8:
        raise ValidationError(
            f"Must be of length 8.  Got: {value} of length {len(value)}"
        )


def validate_logs_bloom(value):
    validate_positive_integer(value)
    if value > UINT2048_MAX:
        raise ValidationError(f"Value exceeds 2048 bit integer size: {value}")


def validate_canonical_address(value):
    validate_bytes(value)
    if not is_canonical_address(value):
        raise ValidationError("Value must be a 20 byte string")


def validate_log_entry_type(value):
    if value not in {"pending", "mined"}:
        raise ValidationError("Log entry type must be one of 'pending' or 'mined'")


LOG_ENTRY_VALIDATORS = {
    "type": validate_log_entry_type,
    "logIndex": validate_positive_integer,
    "transactionIndex": if_not_null(validate_positive_integer),
    "transactionHash": validate_hexstr,
    "blockHash": validate_hexstr,  # if_not_null(validate_32_byte_hash)
    "blockNumber": validate_hexstr,  # if_not_null(validate_positive_integer)
    "address": validate_canonical_address,
    "data": validate_bytes,
    "topics": partial(validate_array, validator=validate_32_byte_hexstr),
}
validate_log_entry = partial(validate_dict, key_validators=LOG_ENTRY_VALIDATORS)


def validate_signature_v(value):
    validate_positive_integer(value)

    if value not in [0, 1, 27, 28] and value not in range(35, UINT256_MAX + 1):
        raise ValidationError(
            "The `v` portion of the signature must be 0, 1, 27, 28 or >= 35"
        )


def validate_y_parity(value):
    validate_positive_integer(value)
    if value not in (0, 1):
        raise ValidationError(
            "The 'v' portion (y_parity) of the signature must be either 0 or 1 for "
            "typed transactions."
        )


def _validate_outbound_access_list(access_list):
    if not is_list_like(access_list):
        raise ValidationError("access_list is not list-like.")
    for entry in access_list:
        if not is_list_like(entry) and len(entry) != 2:
            raise ValidationError(f"access_list entry not properly formatted: {entry}")
        address = entry[0]
        storage_keys = entry[1]
        validate_20_byte_hexstr(address)
        if not is_list_like(storage_keys):
            raise ValidationError(
                f"access_list storage keys are not list-like: {storage_keys}"
            )
        if len(storage_keys) > 0:
            for k in storage_keys:
                validate_32_byte_hexstr(k)


LEGACY_TRANSACTION_VALIDATORS = {
    "type": validate_hexstr,
    "hash": validate_32_byte_hexstr,
    "nonce": validate_hexstr,
    "blockHash": if_not_null(validate_32_byte_hexstr),
    "blockNumber": if_not_null(validate_hexstr),
    "transactionIndex": if_not_null(validate_hexstr),
    "from": validate_20_byte_hexstr,
    "to": if_not_create_address(validate_20_byte_hexstr),
    "value": validate_hexstr,
    "gas": validate_hexstr,
    "gasPrice": validate_hexstr,
    "data": validate_hexstr,
    "v": validate_hexstr,
    "r": validate_hexstr,
    "s": validate_hexstr,
}
validate_legacy_transaction = partial(
    validate_dict, key_validators=LEGACY_TRANSACTION_VALIDATORS
)


ACCESS_LIST_TRANSACTION_VALIDATORS = merge(
    LEGACY_TRANSACTION_VALIDATORS,
    {
        "v": validate_hexstr,
        "yParity": validate_hexstr,
        "chainId": validate_hexstr,
        "accessList": _validate_outbound_access_list,
    },
)
validate_access_list_transaction = partial(
    validate_dict, key_validators=ACCESS_LIST_TRANSACTION_VALIDATORS
)

DYNAMIC_FEE_TRANSACTION_VALIDATORS = merge(
    ACCESS_LIST_TRANSACTION_VALIDATORS,
    {
        "maxFeePerGas": validate_hexstr,
        "maxPriorityFeePerGas": validate_hexstr,
    },
)
validate_dynamic_fee_transaction = partial(
    validate_dict, key_validators=DYNAMIC_FEE_TRANSACTION_VALIDATORS
)

BLOB_TRANSACTION_VALIDATORS = merge(
    DYNAMIC_FEE_TRANSACTION_VALIDATORS,
    {
        "maxFeePerBlobGas": validate_hexstr,
        "blobVersionedHashes": partial(
            validate_array,
            validator=validate_32_byte_hexstr,
        ),
    },
)
validate_blob_transactions = partial(
    validate_dict, key_validators=BLOB_TRANSACTION_VALIDATORS
)

validate_transaction = partial(
    validate_any,
    validators=(
        partial(validate_dict, key_validators=LEGACY_TRANSACTION_VALIDATORS),
        partial(validate_dict, key_validators=ACCESS_LIST_TRANSACTION_VALIDATORS),
        partial(validate_dict, key_validators=DYNAMIC_FEE_TRANSACTION_VALIDATORS),
        partial(validate_dict, key_validators=BLOB_TRANSACTION_VALIDATORS),
    ),
)


WITHDRAWAL_VALIDATORS = {
    "index": validate_hexstr,
    "validatorIndex": validate_hexstr,
    "address": validate_20_byte_hexstr,
    "amount": validate_hexstr,
}
validate_withdrawal = partial(validate_dict, key_validators=WITHDRAWAL_VALIDATORS)


def validate_status(value):
    validate_positive_integer(value)
    if value > 1:
        raise ValidationError(f"Invalid status value '{value}', only 0 or 1 allowed.")


RECEIPT_VALIDATORS = {
    "transactionHash": validate_hexstr,
    "transactionIndex": if_not_null(validate_positive_integer),
    "blockNumber": if_not_null(validate_positive_integer),
    "blockHash": if_not_null(validate_hexstr),
    "cumulativeGasUsed": validate_positive_integer,
    "effectiveGasPrice": if_not_null(validate_positive_integer),
    "from": validate_canonical_address,
    "gasUsed": validate_positive_integer,
    "contractAddress": if_not_null(validate_canonical_address),
    "logs": partial(validate_array, validator=validate_log_entry),
    "stateRoot": validate_bytes,
    "status": validate_status,
    "to": if_not_create_address(validate_canonical_address),
    "type": validate_transaction_type,
}
CANCUN_RECEIPT_VALIDATORS = merge(
    RECEIPT_VALIDATORS,
    {
        "blobGasUsed": validate_positive_integer,
        "blobGasPrice": validate_positive_integer,
    },
)


validate_receipt = partial(
    validate_any,
    validators=(
        partial(validate_dict, key_validators=RECEIPT_VALIDATORS),
        partial(validate_dict, key_validators=CANCUN_RECEIPT_VALIDATORS),
    ),
)


BLOCK_VALIDATORS = {
    "number": validate_positive_integer,
    "hash": validate_hexstr,
    "parentHash": validate_hexstr,
    "nonce": validate_nonce,
    "sha3Uncles": validate_hexstr,
    "logsBloom": validate_logs_bloom,
    "transactionsRoot": validate_hexstr,
    "receiptsRoot": validate_hexstr,
    "stateRoot": validate_hexstr,
    "coinbase": validate_canonical_address,
    "difficulty": validate_positive_integer,
    "mixHash": validate_hexstr,
    "totalDifficulty": validate_positive_integer,
    "size": validate_positive_integer,
    "extraData": validate_hexstr,
    "gasLimit": validate_positive_integer,
    "gasUsed": validate_positive_integer,
    "timestamp": validate_positive_integer,
    "transactions": partial(
        validate_any,
        validators=(
            partial(validate_array, validator=validate_hexstr),
            partial(validate_array, validator=validate_legacy_transaction),
            partial(validate_array, validator=validate_access_list_transaction),
            partial(validate_array, validator=validate_dynamic_fee_transaction),
            partial(validate_array, validator=validate_blob_transactions),
        ),
    ),
    "uncles": partial(validate_array, validator=validate_hexstr),
    # fork-specific fields, validated separately in `_validate_fork_specific_fields()`
    # London fork:
    "baseFeePerGas": identity,
    # Shanghai fork:
    "withdrawals": identity,
    "withdrawalsRoot": identity,
    # Cancun fork:
    "parentBeaconBlockRoot": identity,
    "blobGasUsed": identity,
    "excessBlobGas": identity,
}


def _validate_fork_specific_fields(block):
    """
    If a fork-specific key is present, validate the value appropriately. For
    blocks that are missing this key (before it was introduced via a fork), set the
    value to `None` during validation and pop it back out during normalization.
    """
    if is_london_block(block):
        validate_positive_integer(block["baseFeePerGas"])
    else:
        block["baseFeePerGas"] = None

    if is_shanghai_block(block):
        partial(validate_array, validator=validate_withdrawal)(block["withdrawals"])
        validate_hexstr(block["withdrawalsRoot"])
    else:
        block["withdrawals"] = None
        block["withdrawalsRoot"] = None

    if is_cancun_block(block):
        validate_hexstr(block["parentBeaconBlockRoot"])
        validate_positive_integer(block["blobGasUsed"])
        validate_positive_integer(block["excessBlobGas"])
    else:
        block["parentBeaconBlockRoot"] = None
        block["blobGasUsed"] = None
        block["excessBlobGas"] = None

    return block


validate_block = compose(
    partial(validate_dict, key_validators=BLOCK_VALIDATORS),
    _validate_fork_specific_fields,
)


validate_accounts = partial(validate_array, validator=validate_canonical_address)
