from typing import (
    Annotated,
    Any,
    Dict,
    List,
    Optional,
    Tuple,
    Union,
)

from pydantic import (
    Discriminator,
    Field,
    Tag,
)
from pydantic_core import (
    core_schema,
)

from eth_tester.types.requests.base import (
    BackendContext,
    RequestHexBytes,
    RequestHexInteger,
    RequestModel,
    RequestType,
)

# -- transaction models -- #


class RequestAccountAccess(RequestType):
    """Account access type - an entry in an access list."""

    # TODO: fully implement this class

    _schema = core_schema.any_schema()
    # validator = validate_account_access

    @classmethod
    def serializer(cls, v: Tuple[bytes, Tuple[int]]) -> ...:
        return {
            "address": v[0].hex(),
            "storageKeys": [hex(k) for k in v[1]],
        }


class RequestSetCodeAuthorization(RequestType):
    """Set code authorization type."""

    _schema = core_schema.dict_schema(
        core_schema.str_schema(),
        core_schema.any_schema(),
    )


# -- transaction models -- #
class BaseTransactionRequestModel(RequestModel):
    """Base model for Ethereum transaction requests."""

    chain_id: Optional["RequestHexInteger"] = Field(default=None)
    data: Optional["RequestHexBytes"] = Field(default="0x")
    nonce: Optional["RequestHexInteger"] = Field(default=None)
    gas: Optional["RequestHexInteger"] = Field(default=None)
    sender: "RequestHexBytes" = Field(alias="from")
    to: "RequestHexBytes" = Field(default="0x0000000000000000000000000000000000000000")
    value: Optional["RequestHexInteger"] = Field(default="0x0")

    _key_mapper = {
        BackendContext.PyEVM: {"sender": None},
        BackendContext.EELS: {"gas": "gasLimit"},
    }


class LegacyTransactionRequest(BaseTransactionRequestModel):
    """Legacy transaction type."""

    gas_price: Optional["RequestHexInteger"]
    type: Optional["RequestHexInteger"] = Field(default="0x0")


class SignedLegacyTransactionRequest(LegacyTransactionRequest):
    r: "RequestHexInteger"
    s: "RequestHexInteger"
    v: "RequestHexInteger"

    @property
    def signature(
        self,
    ) -> Tuple["RequestHexInteger", "RequestHexInteger", "RequestHexInteger"]:
        return self.r, self.s, self.v


# -- typed transactions -- #


class TypedTransactionRequest(BaseTransactionRequestModel):
    """Base model for typed transactions."""


class SignedTypedTransactionRequest(TypedTransactionRequest):
    """Base model for signed typed transactions."""

    r: "RequestHexInteger"
    s: "RequestHexInteger"
    y_parity: "RequestHexInteger"

    @property
    def signature(
        self,
    ) -> Tuple["RequestHexInteger", "RequestHexInteger", "RequestHexInteger"]:
        return self.r, self.s, self.y_parity


# -- type 1 tx -- #
class AccessListTransactionRequest(TypedTransactionRequest):
    """EIP-2930 access list transaction type."""

    access_list: List[RequestAccountAccess]
    gas_price: Optional["RequestHexInteger"]
    type: "RequestHexInteger" = Field(exclude=True, default="0x1", frozen=True)


class SignedAccessListTransactionRequest(
    SignedTypedTransactionRequest, AccessListTransactionRequest
):
    """Signed EIP-2930 access list transaction type."""


# -- type 2 tx -- #
class DynamicFeeTransactionRequest(TypedTransactionRequest):
    """EIP-1559 dynamic fee transaction type."""

    access_list: List[RequestAccountAccess] = Field(default_factory=list)
    max_fee_per_gas: Optional["RequestHexInteger"] = None
    max_priority_fee_per_gas: Optional["RequestHexInteger"] = None
    type: "RequestHexInteger" = Field(exclude=True, default="0x2", frozen=True)


class SignedDynamicFeeTransactionRequest(
    SignedTypedTransactionRequest, DynamicFeeTransactionRequest
):
    """Signed EIP-1559 dynamic fee transaction type."""


# -- type 3 tx -- #
class BlobTransactionRequest(TypedTransactionRequest):
    """EIP-4844 blob transaction type."""

    access_list: Optional[List[RequestAccountAccess]] = None
    blob_versioned_hashes: List["RequestHexBytes"] = Field(default_factory=list)
    max_fee_per_blob_gas: Optional["RequestHexInteger"] = None
    max_fee_per_gas: Optional["RequestHexInteger"] = None
    max_priority_fee_per_gas: Optional["RequestHexInteger"] = None
    type: "RequestHexInteger" = Field(exclude=True, default="0x3", frozen=True)


class SignedBlobTransactionRequest(
    SignedTypedTransactionRequest, BlobTransactionRequest
):
    """Signed EIP-4844 blob transaction type."""


# -- type 4 tx -- #
class SetCodeTransactionRequest(TypedTransactionRequest):
    """EIP-7702 set code transaction type."""

    access_list: Optional[List[RequestAccountAccess]] = None
    authorization_list: List[RequestSetCodeAuthorization] = Field(default_factory=list)
    max_fee_per_gas: Optional["RequestHexInteger"] = None
    max_priority_fee_per_gas: Optional["RequestHexInteger"] = None
    type: "RequestHexInteger" = Field(exclude=True, default="0x4", frozen=True)


class SignedSetCodeTransactionRequest(
    SignedTypedTransactionRequest, SetCodeTransactionRequest
):
    """Signed EIP-7702 set code transaction type."""


# -- generic transaction discriminator -- #


def transaction_request_discriminator(v: Dict[str, Any]) -> str:
    """Discriminate transaction request type based on present fields."""
    if not isinstance(v, dict):
        raise ValueError("Transaction must be a dictionary")

    tx_type = v.get("type")
    has_signature_fields = all(sig_field in v for sig_field in ("r", "s", "yParity"))
    has_legacy_signature_fields = all(sig_field in v for sig_field in ("r", "s", "v"))

    if tx_type is not None:
        try:
            type_ = int(tx_type, 16)
        except ValueError:
            raise ValueError(f"Invalid transaction type: {tx_type}")
        match type_:
            case 0:
                return "signed_legacy" if has_legacy_signature_fields else "legacy"
            case 1:
                return "signed_access_list" if has_signature_fields else "access_list"
            case 2:
                return "signed_dynamic_fee" if has_signature_fields else "dynamic_fee"
            case 3:
                return "signed_blob" if has_signature_fields else "blob"
            case 4:
                return "signed_set_code" if has_signature_fields else "set_code"

    has_gas_price = "gasPrice" in v
    has_max_fee_per_gas = "maxFeePerGas" in v
    has_max_priority_fee_per_gas = "maxPriorityFeePerGas" in v
    has_access_list = "accessList" in v

    if "blobVersionedHashes" in v:
        return "signed_blob" if has_signature_fields else "blob"

    if "authorizationList" in v:
        return "signed_set_code" if has_signature_fields else "set_code"

    if has_max_fee_per_gas or has_max_priority_fee_per_gas:
        return "signed_dynamic_fee" if has_signature_fields else "dynamic_fee"

    if has_access_list and has_gas_price:
        return "signed_access_list" if has_signature_fields else "access_list"

    return "signed_legacy" if has_legacy_signature_fields else "legacy"


TransactionRequestObject = Annotated[
    Union[
        Annotated[LegacyTransactionRequest, Tag("legacy")],
        Annotated[SignedLegacyTransactionRequest, Tag("signed_legacy")],
        Annotated[AccessListTransactionRequest, Tag("access_list")],
        Annotated[SignedAccessListTransactionRequest, Tag("signed_access_list")],
        Annotated[DynamicFeeTransactionRequest, Tag("dynamic_fee")],
        Annotated[SignedDynamicFeeTransactionRequest, Tag("signed_dynamic_fee")],
        Annotated[BlobTransactionRequest, Tag("blob")],
        Annotated[SignedBlobTransactionRequest, Tag("signed_blob")],
        Annotated[SetCodeTransactionRequest, Tag("set_code")],
        Annotated[SignedSetCodeTransactionRequest, Tag("signed_set_code")],
    ],
    Discriminator(transaction_request_discriminator),
]
