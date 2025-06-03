from functools import partial
from typing import (
    Any,
    Callable,
    Dict,
)

from pydantic import ConfigDict
from pydantic_core import core_schema

from eth_tester.utils.normalizers import from_hexstr
from eth_utils import (
    CamelModel,
    is_hexstr,
    to_hex,
)
from eth_utils.toolz import (
    merge,
)


class RequestModel(CamelModel):
    model_config = ConfigDict(
        **merge(CamelModel.model_config, {"populate_by_name": False})
    )

    def python_serialize(self) -> Dict[str, Any]:
        """
        Serialize the model to a dictionary with camelCase keys and Python types as
        values.
        """
        return self.model_dump(by_alias=True, mode="python")

    def json_serialize(self) -> Dict[str, Any]:
        """
        Serialize the model to a dictionary with camelCase keys and hex string values.
        """
        return self.model_dump(by_alias=True, mode="json")


# -- base request types -- #
class RequestType:
    """
    Base class for request types. All request types are expected as a hex string
    and should be normalized to the appropriate Python type (int, bytes, str, etc.).
    """

    _schema: core_schema.CoreSchema = None

    # default serializer for serializing to hex strings
    serializer: Callable[..., Any] = to_hex
    normalizer: Callable[..., Any] = None
    strict_length = None

    @classmethod
    def _fill_model(cls, v: Any) -> Any:
        if cls.validator:
            cls.validator(v)
        if cls.normalizer:
            v = cls.normalizer(v)
        if cls.strict_length and len(v) != cls.strict_length:
            raise ValueError(f"Value must have length `{cls.strict_length}`, got `{v}`")
        return v

    @classmethod
    def __get_pydantic_core_schema__(
        cls, _source_type: Any, _handler: Any
    ) -> core_schema.CoreSchema:
        return core_schema.no_info_before_validator_function(
            cls._fill_model,
            cls._schema,
            serialization=core_schema.plain_serializer_function_ser_schema(
                # Only serialize to hex in 'json' mode, use Python types otherwise
                cls.serializer,
                when_used="json",
            ),
        )

    @staticmethod
    def validator(v: Any) -> None:
        if not is_hexstr(v):
            raise ValueError(f"Value must be a hex string, got `{v}`")


class RequestHexInteger(int, RequestType):
    _schema = core_schema.int_schema()
    normalizer = partial(from_hexstr, to_type="int")


class RequestHexBytes(bytes, RequestType):
    _schema = core_schema.bytes_schema()
    normalizer = partial(from_hexstr, to_type="bytes")


class RequestHexStr(str, RequestType):
    _schema = core_schema.str_schema()
