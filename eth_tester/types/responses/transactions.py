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
    RequestType,
)
from eth_tester.types.responses.base import (
    ResponseHexStr,
    ResponseModel,
    SerializedModel,
)

# -- transaction models -- #


class ResponseAccountAccess(RequestType):
    """Account access type - an entry in an access list."""

    # TODO: fully implement this class

    _schema = core_schema.any_schema()
    # validator = validate_account_access

    @classmethod
    def serializer(
        cls, v: Tuple[bytes, Tuple[int]]
    ) -> Dict[str, Union[str, List[str]]]:
        return {
            "address": v[0].hex(),
            "storageKeys": [hex(k) for k in v[1]],
        }


class ResponseSetCodeAuthorization(RequestType):
    """Set code authorization type."""

    _schema = core_schema.dict_schema(
        core_schema.str_schema(),
        core_schema.any_schema(),
    )


# -- transaction models -- #
class BaseTransactionResponseModel(ResponseModel):
    """Base model for Ethereum transaction requests."""

    block_number: "ResponseHexStr"
    block_hash: "ResponseHexStr"
    transaction_index: "ResponseHexStr"
    chain_id: Optional["ResponseHexStr"] = Field(default=None)
    data: Optional["ResponseHexStr"] = Field(default="0x")
    nonce: Optional["ResponseHexStr"] = Field(default=None)
    gas: Optional["ResponseHexStr"] = Field(default=None)
    sender: "ResponseHexStr" = Field(alias="from")
    to: "ResponseHexStr" = Field(default="0x0000000000000000000000000000000000000000")
    value: Optional["ResponseHexStr"] = Field(default="0x0")

    _key_mapper = {
        BackendContext.PyEVM: {"sender": None},
        BackendContext.EELS: {"gas": "gasLimit"},
    }


class LegacyTransactionResponse(BaseTransactionResponseModel):
    """Legacy transaction type."""

    gas_price: Optional["ResponseHexStr"]
    type: "ResponseHexStr" = Field(default="0x0")


class SignedLegacyTransactionResponse(LegacyTransactionResponse):
    r: "ResponseHexStr"
    s: "ResponseHexStr"
    v: "ResponseHexStr"

    @property
    def signature(
        self,
    ) -> Tuple["ResponseHexStr", "ResponseHexStr", "ResponseHexStr"]:
        return self.r, self.s, self.v


# -- typed transactions -- #


class TypedTransactionResponse(BaseTransactionResponseModel):
    """Base model for typed transactions."""


class SignedTypedTransactionResponse(TypedTransactionResponse):
    """Base model for signed typed transactions."""

    r: "ResponseHexStr"
    s: "ResponseHexStr"
    y_parity: "ResponseHexStr"

    @property
    def signature(
        self,
    ) -> Tuple["ResponseHexStr", "ResponseHexStr", "ResponseHexStr"]:
        return self.r, self.s, self.y_parity


# -- type 1 tx -- #
class AccessListTransactionResponse(TypedTransactionResponse):
    """EIP-2930 access list transaction type."""

    access_list: List[ResponseAccountAccess] = Field(default_factory=list)
    gas_price: Optional["ResponseHexStr"]
    type: "ResponseHexStr" = Field(default="0x1", frozen=True)


class SignedAccessListTransactionResponse(
    SignedTypedTransactionResponse, AccessListTransactionResponse
):
    """Signed EIP-2930 access list transaction type."""


# -- type 2 tx -- #
class DynamicFeeTransactionResponse(TypedTransactionResponse):
    """EIP-1559 dynamic fee transaction type."""

    access_list: List[ResponseAccountAccess] = Field(default_factory=list)
    max_fee_per_gas: Optional["ResponseHexStr"] = None
    max_priority_fee_per_gas: Optional["ResponseHexStr"] = None
    type: "ResponseHexStr" = Field(default="0x2", frozen=True)


class SignedDynamicFeeTransactionResponse(
    SignedTypedTransactionResponse, DynamicFeeTransactionResponse
):
    """Signed EIP-1559 dynamic fee transaction type."""


# -- type 3 tx -- #
class BlobTransactionResponse(TypedTransactionResponse):
    """EIP-4844 blob transaction type."""

    access_list: Optional[List[ResponseAccountAccess]] = None
    blob_versioned_hashes: List["ResponseHexStr"] = Field(default_factory=list)
    max_fee_per_blob_gas: Optional["ResponseHexStr"] = None
    max_fee_per_gas: Optional["ResponseHexStr"] = None
    max_priority_fee_per_gas: Optional["ResponseHexStr"] = None
    type: "ResponseHexStr" = Field(default="0x3", frozen=True)


class SignedBlobTransactionResponse(
    SignedTypedTransactionResponse, BlobTransactionResponse
):
    """Signed EIP-4844 blob transaction type."""


# -- type 4 tx -- #
class SetCodeTransactionResponse(TypedTransactionResponse):
    """EIP-7702 set code transaction type."""

    access_list: Optional[List[ResponseAccountAccess]] = None
    authorization_list: List[ResponseSetCodeAuthorization] = Field(default_factory=list)
    max_fee_per_gas: Optional["ResponseHexStr"] = None
    max_priority_fee_per_gas: Optional["ResponseHexStr"] = None
    type: "ResponseHexStr" = Field(default="0x4", frozen=True)


class SignedSetCodeTransactionResponse(
    SignedTypedTransactionResponse, SetCodeTransactionResponse
):
    """Signed EIP-7702 set code transaction type."""


# -- generic transaction discriminator -- #


def transaction_response_discriminator(v: Dict[str, Any]) -> str:
    """Discriminate transaction response type based on present fields."""
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


TransactionRPCResponse = Annotated[
    Union[
        Annotated[SerializedModel[LegacyTransactionResponse], Tag("legacy")],
        Annotated[
            SerializedModel[SignedLegacyTransactionResponse],
            Tag("signed_legacy"),
        ],
        Annotated[SerializedModel[AccessListTransactionResponse], Tag("access_list")],
        Annotated[
            SerializedModel[SignedAccessListTransactionResponse],
            Tag("signed_access_list"),
        ],
        Annotated[SerializedModel[DynamicFeeTransactionResponse], Tag("dynamic_fee")],
        Annotated[
            SerializedModel[SignedDynamicFeeTransactionResponse],
            Tag("signed_dynamic_fee"),
        ],
        Annotated[SerializedModel[BlobTransactionResponse], Tag("blob")],
        Annotated[SerializedModel[SignedBlobTransactionResponse], Tag("signed_blob")],
        Annotated[SerializedModel[SetCodeTransactionResponse], Tag("set_code")],
        Annotated[
            SerializedModel[SignedSetCodeTransactionResponse],
            Tag("signed_set_code"),
        ],
    ],
    Discriminator(transaction_response_discriminator),
]


# -- receipts -- #


class TransactionReceiptResponse(ResponseModel):
    """Transaction receipt response model."""

    _include_if_none = {"contract_address"}

    block_hash: "ResponseHexStr"
    block_number: "ResponseHexStr"
    contract_address: "ResponseHexStr"
    cumulative_gas_used: "ResponseHexStr"
    sender: "ResponseHexStr" = Field(alias="from")
    gas_used: "ResponseHexStr"
    blob_gas_used: Optional["ResponseHexStr"] = None
    effective_gas_price: "ResponseHexStr"
    blob_gas_price: Optional["ResponseHexStr"] = None
    logs: List[Dict[str, Any]] = Field(default_factory=list)
    # logs_bloom: "ResponseHexStr"
    status: Optional["ResponseHexStr"] = None
    to: "ResponseHexStr"
    transaction_hash: "ResponseHexStr"
    transaction_index: "ResponseHexStr"
    state_root: "ResponseHexStr"  # not in specs but geth maybe returns it?


TxReceiptRPCResponse = SerializedModel[TransactionReceiptResponse]
