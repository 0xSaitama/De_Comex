// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {FunctionsClient} from
    "@chainlink/contracts/src/v0.8/functions/dev/v1_0_0/FunctionsClient.sol";
import {FunctionsRequest} from
    "@chainlink/contracts/src/v0.8/functions/dev/v1_0_0/libraries/FunctionsRequest.sol";
import {LibBitmap} from "solady/utils/LibBitmap.sol";
import {IScriptModule} from "./Interfaces/IScriptModule.sol";


/**
 * @title ChainLinkFunction
 * @notice Core contract making HTTP requests using Chainlink function product
 * @dev This contract uses hardcoded values and should not be used in production.
 */
contract ChainlinkFunction is FunctionsClient {
    using FunctionsRequest for FunctionsRequest.Request;
    using LibBitmap for LibBitmap.Bitmap;
    
    // State variables to store the last request ID, response, and error
    bytes32 public s_lastRequestId;
    bytes public s_lastResponse;
    bytes public s_lastError;

    // Custom error type
    error UnexpectedRequestID(bytes32 requestId);
    error RequestAlreadyPending();

    // Event to log responses
    event Response(
        bytes32 indexed requestId, bytes txHash, bytes response, bytes err
    );

    //Callback gas limit
    uint32 public callBackGasLimit = 300_000;

   // donID - Hardcoded for Sepolia
    // Check to get the donID for your supported network https://docs.chain.link/chainlink-functions/supported-networks
    bytes32 donID =
        0x66756e2d657468657265756d2d7365706f6c69612d3100000000000000000000;

    // Router address - Hardcoded for Sepolia
    // Check to get the router address for your supported network https://docs.chain.link/chainlink-functions/supported-networks
    address router = 0xb83E47C2bC239B3bf370bc41e1459A34b41238D0;

    // State variable to store the returned choice information
    mapping(bytes32 => bytes32) public requestIdToTxHash;
    
    LibBitmap.Bitmap private pendingRequests;

    string public spaceID;

    /**
     * @notice Initializes the contract with the Chainlink router address
     */
    constructor() FunctionsClient(router) {}

    function getPendingRequest(bytes32 requestId) external view returns (bool) {
        return pendingRequests.get(uint256(requestId));
    }

    /**
     * @notice Sends an HTTP request for proposal information
     * @param subscriptionId The ID for the Chainlink subscription
     * @param module The module address containing the source code
     * @param argsId The ID to build the request args
     */
    function sendRequest(uint64 subscriptionId, address module, string memory argsId)
        internal
        returns (bytes32 requestId)
    {   
        if (pendingRequests.get(uint256(requestId))) {
            revert RequestAlreadyPending();
        }
        FunctionsRequest.Request memory req;
        req.initializeRequestForInlineJavaScript(IScriptModule(module).source()); // Initialize the request with JS code
        string[] memory args = IScriptModule(module).buildRequestArgs(argsId);
        
        req.setArgs(args); // Set the arguments for the request

        // Send the request and store the request ID
        s_lastRequestId =
            _sendRequest(req.encodeCBOR(), subscriptionId, callBackGasLimit, donID);

        return s_lastRequestId;
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
        requestIdToTxHash[requestId] = bytes32(response);
        s_lastError = err;
        if (err.length == 0) {
            pendingRequests.set(uint256(requestId));
        }

        // Emit an event to log the response
        emit Response(requestId, response, s_lastResponse, s_lastError);
    }
}
