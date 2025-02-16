// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {APIAccount} from "../contracts/APIAccount.sol";

/// @title DeployAPIAccount
/// @dev Simple deploying script.
/// @author 0xSaitama

contract DeployAPIAccount is Test {
    APIAccount public apiAccount;

    function run() public {
        vm.startBroadcast();

        apiAccount = new APIAccount(msg.sender);

        console2.log("Deployer address:");
        console2.log(msg.sender);
        console2.log("______________________");
        console2.log("Deployed APIAccount address:");
        console2.log(address(apiAccount));

        vm.stopBroadcast();
    }
}
