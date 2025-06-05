from typing import (
    Optional,
)

from pydantic import (
    Field,
)

from eth_tester.types.responses.base import (
    ResponseHexStr,
    ResponseModel,
    SerializedModel,
)


class BlockHeaderResponse(ResponseModel):
    """Represents a block header response object."""

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
    base_fee_per_gas: Optional[ResponseHexStr] = None
    withdrawals: Optional[list[ResponseHexStr]] = Field(default=None)
    withdrawals_root: Optional[ResponseHexStr] = None
    parent_beacon_block_root: Optional[ResponseHexStr] = None
    blob_gas_used: Optional[ResponseHexStr] = None
    excess_blob_gas: Optional[ResponseHexStr] = None


BlockRPCResponse = SerializedModel[BlockHeaderResponse]
