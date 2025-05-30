from pydantic import Field

from eth_tester.types.base import (
    EthTesterBaseModel,
)
from eth_tester.types.responses.base import (
    ResponseHexStr,
)


class ResponseBlock(EthTesterBaseModel):
    """Represents a block response in the Ethereum tester."""

    number: ResponseHexStr
    hash: ResponseHexStr
    parentHash: ResponseHexStr
    nonce: ResponseHexStr
    sha3Uncles: ResponseHexStr
    logsBloom: ResponseHexStr
    transactionsRoot: ResponseHexStr
    receiptsRoot: ResponseHexStr
    stateRoot: ResponseHexStr
    coinbase: ResponseHexStr
    difficulty: ResponseHexStr
    totalDifficulty: ResponseHexStr
    mixHash: ResponseHexStr
    size: ResponseHexStr
    extraData: ResponseHexStr
    gasLimit: ResponseHexStr
    gasUsed: ResponseHexStr
    timestamp: ResponseHexStr
    transactions: list[ResponseHexStr] = Field(default_factory=list)
    uncles: list[ResponseHexStr]
    baseFeePerGas: ResponseHexStr
    withdrawals: list[ResponseHexStr] = Field(default_factory=list)
    withdrawalsRoot: ResponseHexStr
    parentBeaconBlockRoot: ResponseHexStr
    blobGasUsed: ResponseHexStr
    excessBlobGas: ResponseHexStr
