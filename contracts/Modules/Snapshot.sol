// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;
import {IScriptModule} from "../Interfaces/IScriptModule.sol";

/**
 * @title Snapshot
 * @notice Script module contract storing source js code to get Snapshot voted proposal execution
 */
contract Snapshot is IScriptModule {
    string public source;
    string public spaceID = "DNS.eth";

    constructor(string memory _spaceID, string memory _source) {
        spaceID = _spaceID;
        source = _source;
    }

    function buildRequestArgs(string memory id) external view returns (string[] memory args) {
        args = new string[](2);
        args[0] = id;
        args[1] = spaceID; 
    }
}