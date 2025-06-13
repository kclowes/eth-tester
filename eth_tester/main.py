import functools
import itertools
import operator
from typing import (
    Any,
    Generator,
    List,
)

from eth_utils import (
    is_integer,
    is_same_address,
    to_hex,
    to_list,
    to_tuple,
)
from eth_utils.toolz import (
    assoc,
    compose,
    dissoc,
    excepts,
    partial,
    remove,
)
from pydantic import (
    validate_call,
)

from eth_tester.backends import (
    get_chain_backend,
)
from eth_tester.constants import (
    ZERO_ADDRESS_HEX,
)
from eth_tester.exceptions import (
    BlockNotFound,
    FilterNotFound,
    SnapshotNotFound,
    TransactionNotFound,
    ValidationError,
)
from eth_tester.types.requests.base import (
    RequestHexBytes,
    RequestHexInteger,
    RequestHexStr,
)
from eth_tester.types.requests.blocks import (
    RequestBlockIdentifier,
)
from eth_tester.types.requests.transactions import (
    DynamicFeeTransactionRequest,
    SignedDynamicFeeTransactionRequest,
    SignedTypedTransactionRequest,
    TransactionRequestObject,
    TypedTransactionRequest,
)
from eth_tester.types.responses.base import (
    ResponseHexStr,
)
from eth_tester.types.responses.blocks import (
    BlockRPCResponse,
)
from eth_tester.types.responses.filters import (
    ResponseFilterRPCResponse,
)
from eth_tester.types.responses.transactions import (
    TransactionRPCResponse,
    TxReceiptRPCResponse,
)
from eth_tester.utils.accounts import (
    private_key_to_address,
)
from eth_tester.utils.filters import (
    Filter,
    check_if_log_matches,
)
from eth_tester.utils.transactions import (
    extract_transaction_type,
    extract_valid_transaction_params,
    remove_matching_transaction_from_list,
)


def backend_proxy_method(backend_method_name):
    def proxy_method(self, *args, **kwargs):
        backend_method = getattr(self.backend, backend_method_name)
        return backend_method(*args, **kwargs)

    return proxy_method


def handle_auto_block_inclusion(func):
    @functools.wraps(func)
    def func_wrapper(self, *args, **kwargs):
        if self.auto_include_transactions:
            transaction_hash = func(self, *args, **kwargs)
            self.include_block()
        else:
            snapshot = self.take_snapshot()
            try:
                transaction_hash = func(self, *args, **kwargs)
                pending_transaction = self.get_transaction_by_hash(transaction_hash)
                # Remove any pending transactions with the same nonce
                self._pending_transactions = remove_matching_transaction_from_list(
                    self._pending_transactions, pending_transaction
                )
                cleaned_transaction = _clean_pending_transaction(pending_transaction)
                self._pending_transactions.append(cleaned_transaction)
            finally:
                self.revert_to_snapshot(snapshot)
        return transaction_hash

    def _clean_pending_transaction(pending_transaction):
        cleaned_transaction = dissoc(pending_transaction, "type")

        # see: https://github.com/ethereum/execution-specs/pull/251
        if "gasPrice" and "maxFeePerGas" in pending_transaction:
            cleaned_transaction = dissoc(cleaned_transaction, "gasPrice")

        return cleaned_transaction

    return func_wrapper


class EthereumTester:
    backend = None
    fork_blocks = None
    auto_include_transactions = None

    def __init__(self, backend=None, auto_include_transactions=True):
        if backend is None:
            backend = get_chain_backend()

        self.backend = backend
        self.chain_id = lambda: int(self.backend.chain.chain_id)

        self.auto_include_transactions = auto_include_transactions
        self._reset_local_state()

    _filter_counter = None
    _log_filters = None
    _block_filters = None
    _pending_transaction_filters = None
    _pending_transactions = []
    _snapshot_counter = None
    _snapshots = None
    _account_passwords = None

    def _reset_local_state(self):
        # filter tracking
        self._filter_counter = itertools.count()
        self._log_filters = {}
        self._block_filters = {}
        self._pending_transaction_filters = {}

        # snapshot tracking
        self._snapshot_counter = itertools.count()
        self._snapshots = {}

        # raw accounts
        self._account_passwords = {}

    # -- time traveling -- #
    def time_travel(self, to_timestamp):
        # make sure we are not traveling back in time as this is not possible.
        current_timestamp = self.backend.get_block_by_number("pending")["timestamp"]
        if to_timestamp == current_timestamp:
            # no change, return immediately
            return
        elif to_timestamp < current_timestamp:
            raise ValidationError(
                "Space time continuum distortion detected.  Traveling backwards "
                "in time violates interdimensional ordinance 31415-926."
            )
        else:
            self.backend.time_travel(to_timestamp)

    # -- accounts -- #
    @validate_call(validate_return=True)
    def get_accounts(self) -> List[ResponseHexStr]:
        raw_accounts = self.backend.get_accounts()
        return raw_accounts

    @validate_call(validate_return=True)
    def add_account(
        self, private_key: RequestHexBytes, password: str = None
    ) -> ResponseHexStr:
        account = private_key_to_address(private_key)
        if any(is_same_address(account, value) for value in self.get_accounts()):
            raise ValidationError("Account already present in account list")

        self.backend.add_account(private_key)
        self._account_passwords[account] = password
        return account

    @validate_call(validate_return=True)
    def get_balance(
        self,
        address: RequestHexStr,
        block_number: RequestBlockIdentifier = "latest",
    ) -> ResponseHexStr:
        return self.backend.get_balance(address, block_number)

    @validate_call(validate_return=True)
    def get_code(
        self,
        address: RequestHexStr,
        block_number: RequestBlockIdentifier = "latest",
    ) -> ResponseHexStr:
        return self.backend.get_code(address, block_number)

    @validate_call(validate_return=True)
    def get_storage_at(
        self,
        address: RequestHexStr,
        slot: RequestHexInteger,
        block_number: RequestBlockIdentifier = "latest",
    ) -> ResponseHexStr:
        return self.backend.get_storage(address, slot, block_number)

    @validate_call(validate_return=True)
    def get_nonce(
        self,
        address: RequestHexStr,
        block_number: RequestBlockIdentifier = "latest",
    ) -> ResponseHexStr:
        return self.backend.get_nonce(address, block_number)

    # -- transactions -- #
    @staticmethod
    def _normalize_pending_transaction(pending_transaction):
        """
        Add the transaction type and, if a dynamic fee transaction, add gasPrice =
        maxFeePerGas as highlighted in the execution-specs link below.
        """
        _type = extract_transaction_type(pending_transaction)
        pending_transaction = assoc(pending_transaction, "type", _type)

        # see: https://github.com/ethereum/execution-specs/pull/251
        int_type = int(_type, 16)
        if int_type >= 2:
            pending_transaction = assoc(
                pending_transaction,
                "gasPrice",
                pending_transaction["maxFeePerGas"],
            )
        return pending_transaction

    def _get_pending_transaction_by_hash(self, transaction_hash: RequestHexBytes):
        for transaction in self._pending_transactions:
            if transaction["hash"] == transaction_hash:
                return transaction
        raise TransactionNotFound(
            f"No transaction found for transaction hash: {transaction_hash}"
        )

    def _fill_transaction_defaults(
        self,
        transaction: TransactionRequestObject,
        block_number: RequestBlockIdentifier = "latest",
        is_estimate_gas: bool = False,
    ) -> None:
        """
        Fill in default values for transaction parameters if not specified.
        """
        default_max_fee = 10**9

        is_dynamic_fee_transaction = isinstance(
            transaction,
            (DynamicFeeTransactionRequest, SignedDynamicFeeTransactionRequest),
        )
        is_typed_transaction = isinstance(transaction, TypedTransactionRequest)

        if not transaction.nonce:
            transaction.nonce = self.backend.get_nonce(transaction.sender, block_number)

        if is_dynamic_fee_transaction:
            if (
                not transaction.max_fee_per_gas
                and not transaction.max_priority_fee_per_gas
            ):
                # set both to default if neither is provided
                transaction.max_priority_fee_per_gas = default_max_fee
                transaction.max_fee_per_gas = default_max_fee
            elif (
                transaction.max_priority_fee_per_gas and not transaction.max_fee_per_gas
            ):
                # calculate max_fee_per_gas based on priority fee and base fee
                base_fee = self.backend.get_base_fee(block_number)
                transaction.max_fee_per_gas = transaction.max_priority_fee_per_gas + (
                    2 * base_fee
                )

        # set chain_id for typed transactions if not already set
        if is_typed_transaction and not transaction.chain_id:
            transaction.chain_id = int(self.backend.chain.chain_id)

        if not transaction.gas and not is_estimate_gas:
            transaction.gas = self.backend.estimate_gas(
                transaction, block_number=block_number
            )

    @validate_call(validate_return=True)
    def get_transaction_by_hash(
        self, transaction_hash: RequestHexBytes
    ) -> TransactionRPCResponse:
        try:
            pending_transaction = self._get_pending_transaction_by_hash(
                transaction_hash
            )
            return self._normalize_pending_transaction(pending_transaction)
        except TransactionNotFound:
            transaction = self.backend.get_transaction_by_hash(transaction_hash)
            return transaction

    @validate_call(validate_return=True)
    def get_block_by_number(
        self,
        block_number: RequestBlockIdentifier,
        full_transactions: bool = False,
    ) -> BlockRPCResponse:
        return self.backend.get_block_by_number(block_number, full_transactions)

    @validate_call(validate_return=True)
    def get_block_by_hash(
        self, block_hash: RequestHexBytes, full_transactions: bool = False
    ) -> BlockRPCResponse:
        return self.backend.get_block_by_hash(block_hash, full_transactions)

    @validate_call(validate_return=True)
    def get_transaction_receipt(
        self, transaction_hash: RequestHexBytes
    ) -> TxReceiptRPCResponse:
        return self.backend.get_transaction_receipt(transaction_hash)

    def get_fee_history(
        self,
        block_count=1,
        newest_block: RequestBlockIdentifier = "latest",
        reward_percentiles: List[int] = (),
    ):
        fee_history = self.backend.get_fee_history(
            block_count, newest_block, reward_percentiles
        )
        return fee_history

    # -- block inclusion -- #
    def enable_auto_transaction_inclusion(self):
        self.auto_include_transactions = True
        if not self.backend.handles_pending_transactions:
            sent_transaction_hashes = self._pop_pending_transactions_to_pending_block()
            self.include_block()
            return sent_transaction_hashes
        else:
            pending_transactions = self.backend._pending_block["transactions"]
            self.include_block()
            return [self.backend._get_tx_hash(tx) for tx in pending_transactions]

    def disable_auto_transactions_inclusion(self):
        self.auto_include_transactions = False

    @validate_call(validate_return=True)
    def include_blocks(
        self, num_blocks: int = 1, coinbase: RequestHexBytes = ZERO_ADDRESS_HEX
    ) -> List[ResponseHexStr]:
        if (
            not self.auto_include_transactions
            and not self.backend.handles_pending_transactions
        ):
            self._pop_pending_transactions_to_pending_block()

        _block_hashes = self.backend.include_blocks(num_blocks, coinbase)
        block_hashes = []
        for blockhash in _block_hashes:
            if not isinstance(blockhash, str):
                block_hashes.append(to_hex(blockhash))

        if len(block_hashes) != num_blocks:
            raise ValidationError(
                f"Invariant: tried to include {num_blocks} blocks.  Got "
                f"{len(block_hashes)} included block hashes."
            )

        # feed the block hashes to any block filters
        for block_hash in block_hashes:
            block = self.get_block_by_hash(block_hash)

            for _, block_filter in self._block_filters.items():
                block_filter.add(block_hash)
            self._process_block_logs(block)

        return block_hashes

    @validate_call(validate_return=True)
    def include_block(
        self, coinbase: RequestHexBytes = ZERO_ADDRESS_HEX
    ) -> ResponseHexStr:
        block_hash = self.include_blocks(1, coinbase=coinbase)[0]
        return block_hash

    # -- private block inclusion API -- #
    def _process_block_logs(self, block: BlockRPCResponse) -> None:
        for _fid, filter_ in self._log_filters.items():
            self._add_log_entries_to_filter(block, filter_)

    def _add_log_entries_to_filter(
        self, block: BlockRPCResponse, filter_: Filter
    ) -> None:
        for transaction_hash in block["transactions"]:
            receipt = self.get_transaction_receipt(transaction_hash)
            for log_entry in receipt["logs"]:
                filter_.add(log_entry)

    def _pop_pending_transactions_to_pending_block(
        self,
    ) -> List[ResponseHexStr]:
        sent_transaction_hashes = self._add_all_to_pending_block(
            self._pending_transactions
        )
        self._pending_transactions.clear()
        return sent_transaction_hashes

    @to_list
    def _add_all_to_pending_block(
        self, pending_transactions: List[TransactionRequestObject]
    ) -> List[ResponseHexStr]:
        for pending in pending_transactions:
            txn = extract_valid_transaction_params(pending)
            yield self._add_transaction_to_pending_block(
                txn, txn_internal_type="send_signed"
            )

    # -- transaction sending -- #
    def _handle_pending_tx_filtering(self, transaction_hash):
        # feed the transaction hash to any pending transaction filters.
        for _, filter_ in self._pending_transaction_filters.items():
            filter_.add(transaction_hash)

    @handle_auto_block_inclusion
    @validate_call
    def send_raw_transaction(self, raw_transaction_hex: RequestHexBytes):
        transaction_hash = self.backend.send_raw_transaction(raw_transaction_hex)
        self._handle_pending_tx_filtering(transaction_hash)
        return transaction_hash

    @validate_call(validate_return=True)
    @handle_auto_block_inclusion
    def send_transaction(self, transaction: TransactionRequestObject) -> ResponseHexStr:
        self._fill_transaction_defaults(transaction)
        return self._add_transaction_to_pending_block(transaction)

    @validate_call(validate_return=True)
    def call(
        self,
        transaction: TransactionRequestObject,
        block_number: RequestBlockIdentifier = "pending",
    ) -> ResponseHexStr:
        self._fill_transaction_defaults(transaction, block_number)
        return self.backend.call(transaction, block_number)

    @validate_call(validate_return=True)
    def estimate_gas(
        self,
        transaction: TransactionRequestObject,
        block_number: RequestBlockIdentifier = "pending",
    ) -> ResponseHexStr:
        self._fill_transaction_defaults(transaction, block_number, is_estimate_gas=True)
        return self.backend.estimate_gas(transaction, block_number)

    # -- private transaction API -- #
    def _add_transaction_to_pending_block(
        self, transaction: TransactionRequestObject
    ) -> ResponseHexStr:
        if isinstance(transaction, SignedTypedTransactionRequest):
            tx_hash = self.backend.send_signed_transaction(transaction)
        else:
            tx_hash = self.backend.send_transaction(transaction)

        self._handle_pending_tx_filtering(tx_hash)
        return tx_hash

    # -- snapshot and revert -- #
    def take_snapshot(self):
        snapshot = self.backend.take_snapshot()
        snapshot_id = next(self._snapshot_counter)
        self._snapshots[snapshot_id] = snapshot
        return snapshot_id

    def revert_to_snapshot(self, snapshot_id):
        try:
            snapshot = self._snapshots[snapshot_id]
        except KeyError:
            raise SnapshotNotFound(f"No snapshot found for id: {snapshot_id}")
        else:
            self.backend.revert_to_snapshot(snapshot)

        for block_filter in self._block_filters.values():
            self._revert_block_filter(block_filter)
        for pending_transaction_filter in self._pending_transaction_filters.values():
            self._revert_pending_transaction_filter(pending_transaction_filter)
        for log_filter in self._log_filters.values():
            self._revert_log_filter(log_filter)

    def reset_to_genesis(self):
        self.backend.reset_to_genesis()
        self._reset_local_state()

    #
    # Private filter API
    #
    def _revert_block_filter(self, filter_: Filter) -> None:
        is_valid_block_hash = excepts(
            (BlockNotFound,),
            compose(
                bool,
                self.get_block_by_hash,
            ),
            lambda v: False,
        )
        values_to_remove = tuple(remove(is_valid_block_hash, filter_.get_all()))
        filter_.remove(*values_to_remove)

    def _revert_pending_transaction_filter(self, filter_):
        is_valid_transaction_hash = excepts(
            (TransactionNotFound,),
            compose(
                bool,
                self.get_transaction_by_hash,
            ),
            lambda v: False,
        )
        values_to_remove = remove(is_valid_transaction_hash, filter_.get_all())
        filter_.remove(*values_to_remove)

    def _revert_log_filter(self, filter_):
        is_valid_transaction_hash = excepts(
            (TransactionNotFound,),
            compose(
                bool,
                self.get_transaction_by_hash,
                operator.itemgetter("transactionHash"),
            ),
            lambda v: False,
        )
        values_to_remove = remove(is_valid_transaction_hash, filter_.get_all())
        filter_.remove(*values_to_remove)

    #
    # Filters
    #
    @validate_call(validate_return=True)
    def create_block_filter(self) -> ResponseHexStr:
        filter_id = next(self._filter_counter)
        self._block_filters[filter_id] = Filter(filter_params=None)
        return ResponseHexStr(filter_id)

    @validate_call(validate_return=True)
    def create_pending_transaction_filter(self) -> ResponseHexStr:
        filter_id = next(self._filter_counter)
        self._pending_transaction_filters[filter_id] = Filter(filter_params=None)
        return ResponseHexStr(filter_id)

    @validate_call(validate_return=True)
    def create_log_filter(
        self,
        from_block: RequestBlockIdentifier = None,
        to_block: RequestBlockIdentifier = None,
        address: List[RequestHexBytes] = None,
        topics: List[RequestHexBytes] = None,
    ) -> ResponseHexStr:
        raw_filter_id = next(self._filter_counter)
        raw_filter_params = {
            "from_block": from_block,
            "to_block": to_block,
            "addresses": address,
            "topics": topics,
        }
        filter_fn = partial(check_if_log_matches, **raw_filter_params)
        new_filter = Filter(
            filter_params=raw_filter_params,
            filter_fn=filter_fn,
        )
        self._log_filters[raw_filter_id] = new_filter

        if is_integer(from_block):
            if is_integer(to_block):
                upper_bound = to_block + 1
            else:
                upper_bound = self.get_block_by_number("pending")["number"]
            for block_number in range(from_block, upper_bound):
                block = self.get_block_by_number(block_number)
                self._add_log_entries_to_filter(block, new_filter)

        return ResponseHexStr(raw_filter_id)

    @validate_call(validate_return=True)
    def delete_filter(self, filter_id: RequestHexInteger) -> None:
        if filter_id in self._block_filters:
            del self._block_filters[filter_id]
        elif filter_id in self._pending_transaction_filters:
            del self._pending_transaction_filters[filter_id]
        elif filter_id in self._log_filters:
            del self._log_filters[filter_id]
        else:
            raise FilterNotFound("Unknown filter id")

    @to_tuple
    @validate_call()
    def get_only_filter_changes(self, filter_id: RequestHexInteger) -> Any:
        if filter_id in self._block_filters:
            filter_ = self._block_filters[filter_id]
            # normalize_fn = self.normalizer.normalize_outbound_block_hash
        elif filter_id in self._pending_transaction_filters:
            filter_ = self._pending_transaction_filters[filter_id]
            # normalize_fn = self.normalizer.normalize_outbound_transaction_hash
        elif filter_id in self._log_filters:
            filter_ = self._log_filters[filter_id]
            # normalize_fn = self.normalizer.normalize_outbound_log_entry
        else:
            raise FilterNotFound("Unknown filter id")

        yield from filter_.get_changes()

    @to_tuple
    @validate_call()
    def get_all_filter_logs(
        self, filter_id: RequestHexInteger
    ) -> Generator[ResponseFilterRPCResponse, None, None]:
        if filter_id in self._block_filters:
            filter_ = self._block_filters[filter_id]
            # normalize_fn = self.normalizer.normalize_outbound_block_hash
        elif filter_id in self._pending_transaction_filters:
            filter_ = self._pending_transaction_filters[filter_id]
            # normalize_fn = self.normalizer.normalize_outbound_transaction_hash
        elif filter_id in self._log_filters:
            filter_ = self._log_filters[filter_id]
            # normalize_fn = self.normalizer.normalize_outbound_log_entry
        else:
            raise FilterNotFound("Unknown filter id")

        yield from filter_.get_all()

    @to_tuple
    @validate_call()
    def get_logs(
        self,
        from_block: RequestBlockIdentifier = None,
        to_block: RequestBlockIdentifier = None,
        address: List[RequestHexBytes] = None,
        topics: List[RequestHexBytes] = None,
    ) -> Generator[ResponseFilterRPCResponse, None, None]:
        # set up the filter object
        raw_filter_params = {
            "from_block": from_block,
            "to_block": to_block,
            "addresses": address,
            "topics": topics,
        }
        filter_fn = partial(
            check_if_log_matches,
            **raw_filter_params,
        )
        log_filter = Filter(
            filter_params=raw_filter_params,
            filter_fn=filter_fn,
        )

        from_block = from_block or "latest"
        to_block = to_block or "latest"

        # Determine lower bound for block range.
        if isinstance(from_block, int):
            lower_bound = from_block
        else:
            lower_bound = self.get_block_by_number(from_block)["number"]

        # Determine upper bound for block range.
        if isinstance(to_block, int):
            upper_bound = to_block
        else:
            upper_bound = self.get_block_by_number(to_block)["number"]

        # Enumerate the blocks in the block range to find all log entries which match.
        for block_number in range(lower_bound, upper_bound + 1):
            block = self.get_block_by_number(block_number)
            for transaction_hash in block["transactions"]:
                receipt = self.get_transaction_receipt(transaction_hash)
                for log_entry in receipt["logs"]:
                    raw_log_entry = self.normalizer.normalize_inbound_log_entry(
                        log_entry
                    )
                    log_filter.add(raw_log_entry)

        # return the matching log entries
        yield from log_filter.get_all()
