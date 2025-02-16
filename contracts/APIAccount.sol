// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ChainlinkFunction} from
    "./ChainlinkFunction.sol";
import {ConfirmedOwner} from
    "@chainlink/contracts/src/v0.8/shared/access/ConfirmedOwner.sol";
import {BatchVerifier} from "./BatchVerifier.sol";
import {LibBitmap} from "solady/utils/LibBitmap.sol";


/**
 * @title APIAccount
 * @notice Core contract making HTTP requests using Chainlink and executing data in the responses
 * @dev This contract uses hardcoded values and should not be used in production.
 */
contract APIAccount is ChainlinkFunction, BatchVerifier, ConfirmedOwner {

    using LibBitmap for LibBitmap.Bitmap;
  
    error WrongBatchHash();
    error TransactionFailed(address target, uint256 value, bytes data);
    error RequestAlreadyExecuted();
    error RequestExpired();

    // Total gas limit per batch
    uint32 public gasLimitPerBatch = 30_000_000;

    // Gas limit per call
    uint32 public gasLimitPerTx = 300_000;

    address public scriptModule;

    LibBitmap.Bitmap private completedRequests;

    constructor(address initialOwner) ConfirmedOwner(initialOwner) {}

    function getCompletedRequest(bytes32 structHash)
        external
        view
        returns (bool)
    {
        return completedRequests.get(uint256(structHash));
    }

    function setCallBackGasLimit(uint32 _callBackGasLimit) external onlyOwner {
        callBackGasLimit = _callBackGasLimit;
    }

    function setGaslimitPerBatch(uint32 _gasLimitPerBatch) external onlyOwner {
        gasLimitPerBatch = _gasLimitPerBatch;
    }

    function setGaslimitPerTx(uint32 _gasLimitPerTx) external onlyOwner {
        gasLimitPerTx = _gasLimitPerTx;
    }

    function setModule(address module) external onlyOwner {
        scriptModule = module;
    }

    function sendRequest(uint64 subscriptionId, string memory argsId) external {
        sendRequest(subscriptionId, scriptModule ,argsId);
    }

     /**
     * @notice Executes a batch of transactions after verifying the txHash from the oracle
     * @param requestId The ID of the request
     * @param transactions The transactions to execute
     */
    function executeTransactionBatch_F45264C(
        bytes32 requestId,
        Transaction[] calldata transactions,
        uint256 deadline
    ) external payable {
        if (completedRequests.get(uint256(requestId))) {
            revert RequestAlreadyExecuted();
        }

        if(block.timestamp > deadline) {
            revert RequestExpired();
        }

        bytes32 batchHash = hashTransactionBatch(transactions, deadline);
        
        // Verify match between batch hash and value returned by the oracle
        if (requestIdToTxHash[requestId] != batchHash) {
            revert WrongBatchHash();
        }
        for (uint256 i = 0; i < transactions.length; i++) {
            Transaction memory transaction = transactions[i];
            (bool success,) = transaction.target.call{
                value: transaction.value,
                gas: gasLimitPerTx
            }(transaction.data);
            if (!success) {
                revert TransactionFailed(
                    transaction.target, transaction.value, transaction.data
                );
            }
        }
        completedRequests.set(uint256(requestId));
    }
}
