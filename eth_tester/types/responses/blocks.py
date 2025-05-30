from pydantic import (
    Field,
)

from eth_tester.types.responses.base import (
    ResponseHexStr,
    ResponseModel,
    SerializedModel,
)


class ResponseBlock(ResponseModel):
    """Represents a block response in the Ethereum tester."""

    number: ResponseHexStr
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
    transactions: list[ResponseHexStr] = Field(default_factory=list)
    uncles: list[ResponseHexStr]
    base_fee_per_gas: ResponseHexStr
    withdrawals: list[ResponseHexStr] = Field(default_factory=list)
    withdrawals_root: ResponseHexStr
    parent_beacon_block_root: ResponseHexStr
    blob_gas_used: ResponseHexStr
    excess_blob_gas: ResponseHexStr


BlockRPCResponse = SerializedModel[ResponseBlock]
