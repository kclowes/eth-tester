from typing import (
    Any,
    Dict,
    Generic,
    TypeVar,
    get_args,
)

from eth_utils import (
    CamelModel,
    to_hex,
)
from pydantic_core import (
    core_schema,
)

# -- base response models -- #


class ResponseModel(CamelModel):
    def serialize(self) -> Dict[str, Any]:
        return self.model_dump(by_alias=True)


T = TypeVar("T", bound=ResponseModel)


class SerializedModel(Dict[str, Any], Generic[T]):
    """Type for serialized models that preserves reference to source model type."""

    @classmethod
    def __get_pydantic_core_schema__(cls, source_type, handler):
        # extract model type from SerializedModel[Model]
        model_cls = get_args(source_type)[0]

        def validate_and_serialize(v, _info):
            return model_cls.model_validate(v).serialize()

        return core_schema.with_info_before_validator_function(
            validate_and_serialize,
            core_schema.dict_schema(),
            serialization=core_schema.to_string_ser_schema(),
        )


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
