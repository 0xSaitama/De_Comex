// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import {APIAccount} from "../../contracts/APIAccount.sol";

contract APIAccountHarness is APIAccount {
    constructor(address initialOwner) APIAccount(initialOwner) {}

    function setRequestIdToTxHash(bytes32 requestId, bytes32 txHash) external {
        requestIdToTxHash[requestId] = txHash;
    }

    function hashTransactionBatchHelper(
        Transaction[] calldata transactions,
        uint256 deadline
    ) public view returns (bytes32) {
        return hashTransactionBatch(transactions, deadline);
    }
}