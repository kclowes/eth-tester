from typing import (
    Any,
    Callable,
)

from eth_utils import (
    is_hexstr,
)
from pydantic_core import (
    core_schema,
)

from eth_tester.types.requests.base import (
    BackendContext,
    RequestType,
)
from eth_tester.utils.normalizers import (
    normalize_block_id,
)


class RequestBlockIdentifier(RequestType):
    """
    Base class for block identifiers. All block identifiers are expected as a hex string
    and should be normalized to the appropriate Python type (int, bytes, str, etc.).
    """

    _str_ids = {"latest", "earliest", "pending", "safe", "finalized"}
    _schema = core_schema.str_schema()
    normalizer = normalize_block_id

    @classmethod
    def validator(cls, v: Any) -> None:
        if not is_hexstr(v) and v not in cls._str_ids:
            raise ValueError(
                f"Value must be a hex string or one of {cls._str_ids}, got `{v}`"
            )

    @classmethod
    def _get_serializer_for_current_backend(
        cls, backend: BackendContext
    ) -> Callable[[Any], Any]:
        """Get serializer for the current backend."""
        return str
