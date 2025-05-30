from abc import (
    ABCMeta,
    abstractmethod,
)
from typing import (
    TYPE_CHECKING,
    Union,
)

from eth_tester.constants import (
    ZERO_ADDRESS,
)

if TYPE_CHECKING:
    from eth_tester.types.requests.base import (
        RequestHexBytes,
        RequestHexInteger,
        RequestHexStr,
    )
    from eth_tester.types.requests.blocks import (
        RequestBlockIdentifier,
    )
    from eth_tester.types.requests.transactions import (
        TransactionRequestObject,
    )
    from eth_tester.types.responses.base import (
        ResponseHexStr,
    )


class BaseChainBackend(metaclass=ABCMeta):
    handles_pending_transactions: bool = False

    # -- snapshots -- #
    @abstractmethod
    def take_snapshot(self) -> int:
        raise NotImplementedError("Must be implemented by subclasses")

    @abstractmethod
    def revert_to_snapshot(self, snapshot: int) -> None:
        raise NotImplementedError("Must be implemented by subclasses")

    @abstractmethod
    def reset_to_genesis(self) -> None:
        raise NotImplementedError("Must be implemented by subclasses")

    # -- meta -- #
    @abstractmethod
    def time_travel(self, to_timestamp: int) -> None:
        raise NotImplementedError("Must be implemented by subclasses")

    # -- mining -- #
    @abstractmethod
    def mine_blocks(
        self, num_blocks: int = 1, coinbase: "RequestHexStr" = ZERO_ADDRESS
    ) -> None:
        raise NotImplementedError("Must be implemented by subclasses")

    # -- accounts -- #
    @abstractmethod
    def get_accounts(self):
        raise NotImplementedError("Must be implemented by subclasses")

    @abstractmethod
    def add_account(self, private_key: "RequestHexBytes") -> "ResponseHexStr":
        raise NotImplementedError("Must be implemented by subclasses")

    # -- chain data -- #
    @abstractmethod
    def get_block_by_number(
        self, block_identifier: "RequestBlockIdentifier", full_transaction: bool = True
    ):
        raise NotImplementedError("Must be implemented by subclasses")

    @abstractmethod
    def get_block_by_hash(
        self, block_hash: "RequestHexBytes", full_transaction: bool = True
    ):
        raise NotImplementedError("Must be implemented by subclasses")

    @abstractmethod
    def get_transaction_by_hash(self, transaction_hash: "RequestHexBytes"):
        raise NotImplementedError("Must be implemented by subclasses")

    @abstractmethod
    def get_transaction_receipt(self, transaction_hash: "RequestHexBytes"):
        raise NotImplementedError("Must be implemented by subclasses")

    # -- account state -- #
    @abstractmethod
    def get_nonce(
        self, address: "RequestHexStr", block_identifier: "RequestBlockIdentifier"
    ) -> int:
        raise NotImplementedError("Must be implemented by subclasses")

    @abstractmethod
    def get_balance(self, address: "RequestHexStr", block_identifier) -> int:
        raise NotImplementedError("Must be implemented by subclasses")

    @abstractmethod
    def get_code(
        self, address: "RequestHexStr", block_identifier: "RequestBlockIdentifier"
    ) -> bytes:
        raise NotImplementedError("Must be implemented by subclasses")

    @abstractmethod
    def get_storage(
        self,
        address: "RequestHexStr",
        slot: "RequestHexInteger",
        block_identifier: "RequestBlockIdentifier",
    ) -> int:
        raise NotImplementedError("Must be implemented by subclasses")

    # -- transactions -- #
    @abstractmethod
    def send_transaction(self, transaction: "TransactionRequestObject") -> str:
        raise NotImplementedError("Must be implemented by subclasses")

    @abstractmethod
    def send_signed_transaction(self, transaction: "TransactionRequestObject") -> str:
        raise NotImplementedError("Must be implemented by subclasses")

    @abstractmethod
    def estimate_gas(
        self,
        transaction: "TransactionRequestObject",
        block_identifier: "RequestBlockIdentifier",
    ) -> int:
        raise NotImplementedError("Must be implemented by subclasses")

    @abstractmethod
    def call(
        self,
        transaction: "TransactionRequestObject",
        block_identifier: "RequestBlockIdentifier",
    ) -> Union[bytes, str]:
        raise NotImplementedError("Must be implemented by subclasses")
