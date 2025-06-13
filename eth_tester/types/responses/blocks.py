from typing import (
    Optional,
    Union,
)

from pydantic import (
    Field,
)

from eth_tester.types.responses.base import (
    ResponseHexStr,
    ResponseModel,
    SerializedModel,
)
from eth_tester.types.responses.transactions import (
    ResponseAccountAccess,
)


class FullTransactionBlockResponse(ResponseModel):
    access_list: ResponseAccountAccess
    block_hash: ResponseHexStr
    block_number: ResponseHexStr
    chain_id: ResponseHexStr = Field(default=None)
    data: ResponseHexStr = Field(default="0x")
    gas: ResponseHexStr = Field(default=None)
    gasPrice: ResponseHexStr = Field(default=None)
    hash: ResponseHexStr
    input: ResponseHexStr
    maxFeePerGas: ResponseHexStr
    maxPriorityFeePerGas: ResponseHexStr
    nonce: Optional["ResponseHexStr"] = Field(default=None)
    sender: "ResponseHexStr" = Field(alias="from")
    to: "ResponseHexStr" = Field(default="0x0000000000000000000000000000000000000000")
    transaction_index: "ResponseHexStr"
    value: ResponseHexStr
    type: ResponseHexStr
    v: ResponseHexStr
    r: ResponseHexStr
    s: ResponseHexStr
    y_parity: ResponseHexStr


class BlockHeaderResponse(ResponseModel):
    """Represents a block header response object."""

    _include_if_none = {"number"}

    number: int  # TODO - put back to ResponseHexStr
    hash: ResponseHexStr
    parent_hash: ResponseHexStr
    nonce: ResponseHexStr
    sha3_uncles: ResponseHexStr
    logs_bloom: ResponseHexStr
    transactions_root: ResponseHexStr
    receipts_root: ResponseHexStr
    state_root: ResponseHexStr
    coinbase: ResponseHexStr
    difficulty: ResponseHexStr
    total_difficulty: ResponseHexStr
    mix_hash: ResponseHexStr
    size: ResponseHexStr
    extra_data: ResponseHexStr
    gas_limit: ResponseHexStr
    gas_used: ResponseHexStr
    timestamp: ResponseHexStr
    transactions: list[Union[FullTransactionBlockResponse, ResponseHexStr]] = Field(
        default_factory=list
    )
    uncles: list[ResponseHexStr]
    base_fee_per_gas: Optional[ResponseHexStr] = None
    withdrawals: Optional[list[ResponseHexStr]] = Field(default=None)
    withdrawals_root: Optional[ResponseHexStr] = None
    parent_beacon_block_root: Optional[ResponseHexStr] = None
    blob_gas_used: Optional[ResponseHexStr] = None
    excess_blob_gas: Optional[ResponseHexStr] = None


BlockRPCResponse = SerializedModel[BlockHeaderResponse]
