from typing import (
    List,
)

from pydantic import (
    Field,
)

from eth_tester.types.responses.base import (
    ResponseHexStr,
    ResponseModel,
    SerializedModel,
)


class ResponseFilterModel(ResponseModel):
    """Response model for filter logs."""

    log_index: ResponseHexStr
    removed: bool
    block_number: ResponseHexStr
    block_hash: ResponseHexStr
    transaction_hash: ResponseHexStr
    transaction_index: ResponseHexStr
    address: ResponseHexStr
    data: ResponseHexStr = Field(default="0x")
    topics: List[ResponseHexStr] = Field(default=[])


ResponseFilterRPCResponse = SerializedModel[ResponseFilterModel]
