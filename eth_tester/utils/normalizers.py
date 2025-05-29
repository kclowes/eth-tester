from typing import (
    Literal,
    Union,
)

from eth_utils import (
    is_hexstr,
    to_bytes,
    to_int,
)


def from_hexstr(
    v: str, to_type: Union[Literal["int"], Literal["bytes"]]
) -> Union[int, bytes]:
    """
    Convert a hex string to an integer.
    """
    if to_type == "int":
        return to_int(hexstr=v)
    elif to_type == "bytes":
        return to_bytes(hexstr=v)
    raise ValueError(f"Invalid type: {type}. Must be 'int' or 'bytes'.")


def normalize_block_id(v: str) -> Union[int, str]:
    if is_hexstr(v):
        return int(v, 16)
    return v
