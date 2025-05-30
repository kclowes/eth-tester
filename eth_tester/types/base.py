# -- base models -- #
from typing import (
    Any,
    Dict,
)

from eth_utils import (
    CamelModel,
)
from eth_utils.toolz import (
    merge,
)
from pydantic import (
    ConfigDict,
)


class EthTesterBaseModel(CamelModel):
    model_config = ConfigDict(
        **merge(CamelModel.model_config, {"populate_by_name": False})
    )

    def serialize(self) -> Dict[str, Any]:
        return self.model_dump(by_alias=True)
