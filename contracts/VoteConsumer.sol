// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import {FunctionsClient} from "@chainlink/contracts/src/v0.8/functions/dev/v1_0_0/FunctionsClient.sol";
import {ConfirmedOwner} from "@chainlink/contracts/src/v0.8/shared/access/ConfirmedOwner.sol";
import {FunctionsRequest} from "@chainlink/contracts/src/v0.8/functions/dev/v1_0_0/libraries/FunctionsRequest.sol";


/**
 * @title VoteConsumer
 * @notice Core contract making HTTP requests to Snapshot API using Chainlink
 * @dev This contract uses hardcoded values and should not be used in production.
 */
contract VoteConsumer is FunctionsClient, ConfirmedOwner {
    using FunctionsRequest for FunctionsRequest.Request;

    error WrongBatchHash(bytes32 requestId);
    error TransactionFailed(address target, uint256 value, bytes data);

    struct Transaction {
        address target;
        bytes data;
        uint256 value;
    }

    // State variables to store the last request ID, response, and error
    bytes32 public s_lastRequestId;
    bytes public s_lastResponse;
    bytes public s_lastError;



    // Custom error type
    error UnexpectedRequestID(bytes32 requestId);

    // Event to log responses
    event Response(
        bytes32 indexed requestId,
        bytes txHash,
        bytes response,
        bytes err
    );

    // Router address - Hardcoded for Sepolia
    // Check to get the router address for your supported network https://docs.chain.link/chainlink-functions/supported-networks
    address router = 0xb83E47C2bC239B3bf370bc41e1459A34b41238D0;

    // JavaScript source code
    // Fetch txHash from a snapshot proposal.
    string public source;

    //Callback gas limit
    uint32 gasLimit = 300000;

    // donID - Hardcoded for Sepolia
    // Check to get the donID for your supported network https://docs.chain.link/chainlink-functions/supported-networks
    bytes32 donID =
        0x66756e2d657468657265756d2d7365706f6c69612d3100000000000000000000;

    // State variable to store the returned choice information
    mapping(bytes32 => bytes) public requestIdToTxHash;

    /**
     * @notice Initializes the contract with the Chainlink router address and sets the contract owner
     */
    constructor() FunctionsClient(router) ConfirmedOwner(msg.sender) {}

    function setSource(string memory _source) external onlyOwner {
        source = _source;
    }

    /**
     * @notice Sends an HTTP request for proposal information
     * @param subscriptionId The ID for the Chainlink subscription
     * @param args The arguments to pass to the HTTP request
     * @return requestId The ID of the request
     */
    function sendRequest(
        uint64 subscriptionId,
        string[] calldata args
    ) external onlyOwner returns (bytes32 requestId) {
        FunctionsRequest.Request memory req;
        req.initializeRequestForInlineJavaScript(source); // Initialize the request with JS code
        if (args.length > 0) req.setArgs(args); // Set the arguments for the request

        // Send the request and store the request ID
        s_lastRequestId = _sendRequest(
            req.encodeCBOR(),
            subscriptionId,
            gasLimit,
            donID
        );

        return s_lastRequestId;
    }

    function executeTransactionBatch(bytes32 requestId, Transaction[] calldata transactions) external payable {
        bytes32 batchHash = keccak256(abi.encode(transactions));
        // Verify that the batch hash matches the one returned by the oracle
        if(bytes32(requestIdToTxHash[requestId]) != batchHash) {
            revert WrongBatchHash(requestId);
        }
        for (uint256 i = 0; i < transactions.length; i++) {
            Transaction memory transaction = transactions[i];
            (bool success, ) = transaction.target.call{value: transaction.value}(
                transaction.data
            );
            if (!success) {
                revert TransactionFailed(transaction.target, transaction.value, transaction.data);
            }
        }
    }

    /**
     * @notice Callback function for fulfilling a request
     * @param requestId The ID of the request to fulfill
     * @param response The HTTP response data
     * @param err Any errors from the Functions request
     */
    function fulfillRequest(
        bytes32 requestId,
        bytes memory response,
        bytes memory err
    ) internal override {
        if (s_lastRequestId != requestId) {
            revert UnexpectedRequestID(requestId); // Check if request IDs match
        }
        // Update the contract's state variables with the response and any errors
        s_lastResponse = response;
        requestIdToTxHash[requestId] = response;
        s_lastError = err;

        // Emit an event to log the response
        emit Response(requestId, response, s_lastResponse, s_lastError);
    }
}
