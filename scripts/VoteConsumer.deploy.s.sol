// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity 0.8.19;

import "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {VoteConsumer} from "../contracts/VoteConsumer.sol";

/// @title DeployVoteConsumer
/// @dev Simple deploying script.
/// @author 0xSaitama

contract DeployVoteConsumer is Test {
    VoteConsumer public voteConsumer;

    function run() public {
        vm.startBroadcast();

        voteConsumer = new VoteConsumer();



        console2.log("Deployer address:");
        console2.log(msg.sender);
        console2.log("______________________");
        console2.log("Deployed VoteConsumer address:");
        console2.log(address(voteConsumer));

        vm.stopBroadcast();
    }
}
