from typing import (
    List,
    Optional,
)

from pydantic import (
    Field,
)

from eth_tester.types.requests.base import (
    RequestHexBytes,
    RequestType,
)
from eth_tester.types.requests.blocks import (
    RequestBlockIdentifier,
)


class RequestLogFilterParams(RequestType):
    from_block: Optional[RequestBlockIdentifier] = Field(default="latest")
    to_block: Optional[RequestBlockIdentifier] = Field(default="latest")
    address: Optional[List[RequestHexBytes]]
    topics: Optional[List[RequestHexBytes]]
