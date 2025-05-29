from typing import (
    Any,
)

from eth_utils import (
    to_hex,
)
from pydantic import (
    RootModel,
)
from pydantic_core import (
    core_schema,
)

RootModel


# -- base types -- #
class ResponseHexStr(str):
    """
    Base class for response types. All response types are expected as ``Any`` and
    should be normalized to hex strings.
    """

    @classmethod
    def _fill_model(cls, v) -> str:
        if isinstance(v, str):
            return to_hex(hexstr=v)
        return to_hex(v)

    @classmethod
    def __get_pydantic_core_schema__(
        cls, _source_type: Any, _handler: Any
    ) -> core_schema.CoreSchema:
        return core_schema.no_info_before_validator_function(
            cls._fill_model,
            core_schema.any_schema(),
            serialization=core_schema.to_string_ser_schema(),
        )
