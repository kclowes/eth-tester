from contextvars import (
    ContextVar,
)
from enum import (
    Enum,
)
from functools import (
    wraps,
)
from typing import (
    TypeVar,
)

T = TypeVar("T")


class BackendContext(str, Enum):
    PyEVM = "py-evm"
    EELS = "eels"


current_backend: ContextVar[BackendContext] = ContextVar(
    "current_backend", default=BackendContext.EELS
)


def with_backend_context(backend_type):
    """
    Class decorator that ensures all methods execute with the correct backend context.
    Handles static methods appropriately.
    """

    def decorator(cls):
        # Set the backend context as a class attribute
        cls._backend_context = backend_type

        # Find all methods to wrap (exclude special methods)
        for name, attr in list(cls.__dict__.items()):
            if callable(attr) and not name.startswith("__"):
                original_method = attr

                is_static = isinstance(attr, staticmethod)

                @wraps(original_method)
                def wrapped_method(*args, _original_method=original_method, **kwargs):
                    # use the context manager to set and reset the context
                    token = current_backend.set(cls._backend_context)
                    try:
                        return _original_method(*args, **kwargs)
                    finally:
                        current_backend.reset(token)

                # if the original was a static method, the wrapped one should be too
                if is_static:
                    wrapped_method = staticmethod(wrapped_method)

                setattr(cls, name, wrapped_method)

        return cls

    return decorator
