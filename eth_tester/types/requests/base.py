from contextvars import (
    ContextVar,
)
from dataclasses import (
    dataclass,
)
from enum import (
    Enum,
)
from functools import (
    partial,
)
from typing import (
    Any,
    Callable,
    Dict,
    Final,
)

from eth_utils import (
    CamelModel,
    is_hexstr,
    to_hex,
)
from eth_utils.functional import (
    identity,
)
from eth_utils.toolz import (
    merge,
)
from pydantic import (
    ConfigDict,
)
from pydantic_core import (
    core_schema,
)

from eth_tester.utils.normalizers import (
    from_hexstr,
)


class BackendContext(str, Enum):
    PyEVM = "py-evm"
    EELS = "eels"


current_backend: ContextVar[BackendContext] = ContextVar(
    "current_backend", default=BackendContext.EELS
)


@dataclass
class BackendConfig:
    """Configuration for how to serialize for a specific backend."""

    integer_serializer: Callable[..., Any]
    bytes_serializer: Callable[..., Any]


BACKEND_SERIALIZER_CONFIG: Final = {
    BackendContext.PyEVM: BackendConfig(
        integer_serializer=identity,  # int
        bytes_serializer=identity,  # bytes
    ),
    BackendContext.EELS: BackendConfig(
        integer_serializer=to_hex,
        bytes_serializer=to_hex,
    ),
}


# -- base models -- #
class RequestModel(CamelModel):
    model_config = ConfigDict(
        **merge(CamelModel.model_config, {"populate_by_name": False})
    )

    def serialize(self) -> Dict[str, Any]:
        """Serialize the model using the current backend context."""
        return self.model_dump(by_alias=True)


# -- base types -- #
class RequestType:
    """
    Base class for request types. All request types are expected as a hex string
    and should be normalized to the appropriate Python type (int, bytes, str, etc.).
    """

    _schema: core_schema.CoreSchema = None

    normalizer: Callable[..., Any] = None
    strict_length = None

    @classmethod
    def _get_backend_config(cls, backend: BackendContext) -> BackendConfig:
        """Get backend-specific serializer configuration."""
        config = BACKEND_SERIALIZER_CONFIG.get(backend)
        if config is None:
            raise ValueError(f"No serializer config found for backend: {backend}")
        return config

    @classmethod
    def _get_serializer_for_current_backend(
        cls, backend: BackendContext
    ) -> Callable[[Any], Any]:
        """Get the appropriate serializer for this type and backend."""
        # default to ``to_hex`` for serialization
        return to_hex

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
        def backend_aware_serializer(value) -> Any:
            backend = current_backend.get()
            serializer = cls._get_serializer_for_current_backend(backend)
            return serializer(value)

        return core_schema.no_info_before_validator_function(
            # fill the model with the normalized value
            cls._fill_model,
            cls._schema,
            # use the backend-aware serializer for serialization
            serialization=core_schema.plain_serializer_function_ser_schema(
                backend_aware_serializer,
            ),
        )

    @staticmethod
    def validator(v: Any) -> None:
        if not is_hexstr(v):
            raise ValueError(f"Value must be a hex string, got `{v}`")


class RequestHexInteger(int, RequestType):
    _schema = core_schema.int_schema()
    normalizer = partial(from_hexstr, to_type="int")

    @classmethod
    def _get_serializer_for_current_backend(
        cls, backend: BackendContext
    ) -> Callable[[int], Any]:
        """Get integer serializer for the current backend."""
        config = cls._get_backend_config(backend)
        return config.integer_serializer


class RequestHexBytes(bytes, RequestType):
    _schema = core_schema.bytes_schema()
    normalizer = partial(from_hexstr, to_type="bytes")

    @classmethod
    def _get_serializer_for_current_backend(
        cls, backend: BackendContext
    ) -> Callable[[bytes], Any]:
        """Get bytes serializer for the current backend."""
        config = cls._get_backend_config(backend)
        return config.bytes_serializer


class RequestHexStr(str, RequestType):
    _schema = core_schema.str_schema()
