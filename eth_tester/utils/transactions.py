from typing import (
    TYPE_CHECKING,
)

from eth_utils import (
    to_list,
)

from eth_tester.constants import (
    DYNAMIC_FEE_TX_TYPE,
)

VALID_TRANSACTION_PARAMS = [
    "type",
    "chainId",
    "from",
    "to",
    "gas",
    "gasPrice",
    "maxFeePerGas",
    "maxPriorityFeePerGas",
    "value",
    "data",
    "nonce",
    "accessList",
    "r",
    "s",
    "v",
]

if TYPE_CHECKING:
    from eth_tester.types.responses.blocks import (
        BlockHeaderResponse,
    )


def extract_valid_transaction_params(transaction_params):
    return {
        key: transaction_params[key]
        for key in VALID_TRANSACTION_PARAMS
        if key in transaction_params
    }


def extract_transaction_type(transaction):
    if isinstance(transaction, dict):
        return (
            "0x2"
            if "maxFeePerGas" in transaction
            else (
                "0x1"
                if "maxFeePerGas" not in transaction and "accessList" in transaction
                else "0x0"
            )
        )
    else:
        # Typed transactions
        return (
            "0x2"
            if hasattr(transaction, "max_fee_per_gas")
            else (
                "0x1"
                if not hasattr(transaction, "max_fee_per_gas")
                and hasattr(transaction, "access_list")
                else "0x0"
            )
        )


@to_list
def remove_matching_transaction_from_list(transaction_list, transaction):
    for tx in transaction_list:
        nonce_equal = transaction["nonce"] == tx["nonce"]
        from_equal = transaction["from"] == tx["from"]
        match = nonce_equal and from_equal
        if not match:
            yield tx


def calculate_effective_gas_price(transaction, block_header: "BlockHeaderResponse"):
    transaction_type = int(extract_transaction_type(transaction), 16)

    if transaction_type < DYNAMIC_FEE_TX_TYPE:
        return int(
            (
                transaction["gasPrice"]
                if isinstance(transaction, dict)
                else hex(transaction.gas_price)
            ),
            16,
        )
    else:
        if isinstance(transaction, dict):
            max_fee = int(transaction["maxFeePerGas"], 16)
            max_priority_fee = int(transaction["maxPriorityFeePerGas"], 16)
        else:
            max_fee = int(transaction.max_fee_per_gas)
            max_priority_fee = int(transaction.max_priority_fee_per_gas)

        base_fee = int(
            block_header["base_fee_per_gas"]
            if isinstance(block_header, dict)
            else block_header.base_fee_per_gas
        )
        return min(max_fee, max_priority_fee + base_fee)
