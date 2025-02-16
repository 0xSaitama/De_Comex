// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {APIAccount} from "../contracts/APIAccount.sol";

/// @title DeployAPIAccount
/// @dev Simple deploying script.
/// @author 0xSaitama

contract RequestAPIAccount is Test {
    APIAccount public apiAccount;
    address payable public constant deployedAPIAccount = payable(address(0xA53Ba7B375b82C18475eC2658Bd9963f093D3B48));
    uint64 public constant subscriptionId = 1797;
    string public constant proposalID = "0x62a6d001c944811913b4d539b70334aa3f3054efb45a07509b06f5c940892b1c";

    function run() public {
        vm.startBroadcast();

        apiAccount = APIAccount(deployedAPIAccount);

        apiAccount.sendRequest(subscriptionId, proposalID);

        vm.stopBroadcast();
    }
}
