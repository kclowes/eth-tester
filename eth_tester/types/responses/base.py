from typing import (
    Any,
    Dict,
    Generic,
    Optional,
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
    _include_if_none: Optional[set[str]] = None

    model_config = CamelModel.model_config.copy()
    model_config.update(extra="forbid")

    def serialize(self) -> Dict[str, Any]:
        serialized = self.model_dump(by_alias=True)

        force_include = self._include_if_none or set()
        result: Dict[str, Any] = {}
        for field_name, field_info in self.__class__.model_fields.items():
            key = field_info.alias if field_info.alias else field_name

            if key in serialized or field_name in force_include:
                # force-include ``_include_if_none`` fields when serializing
                result[key] = serialized.get(key, None)

        return result


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
            serialization=core_schema.wrap_serializer_function_ser_schema(
                lambda v, info: v.serialize()
            ),
        )


# -- base types -- #
class ResponseHexStr(str):
    """
    Base class for response types. All response types are expected as ``Any`` and
    should be normalized to hex strings.
    """

    @classmethod
    def _fill_model(cls, v) -> Optional[str]:
        if isinstance(v, str):
            return to_hex(hexstr=v)
        return to_hex(v) if v else None

    @classmethod
    def __get_pydantic_core_schema__(
        cls, _source_type: Any, _handler: Any
    ) -> core_schema.CoreSchema:
        return core_schema.no_info_before_validator_function(
            cls._fill_model,
            core_schema.any_schema(),
            serialization=core_schema.to_string_ser_schema(),
        )
