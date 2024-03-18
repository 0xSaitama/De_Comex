// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity 0.8.19;

import "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {VoteConsumer} from "../contracts/VoteConsumer.sol";

/// @title DeployVoteConsumer
/// @dev Simple deploying script.
/// @author 0xSaitama

contract RequestVoteConsumer is Test {
    VoteConsumer public voteConsumer;
     address payable public constant deployedVoteConsumer = payable(address(0x78855F78F1669D30a2B766b038D203266f7Adc3D));

    function run() public {
        vm.startBroadcast();

        voteConsumer = VoteConsumer(deployedVoteConsumer);

        string[] memory args = new string[](2);
        args[0] = "0x8e920cae20a3cefd1ec6f926f3d2b57548180a6add9ad59687f2d89ff5c66e59";
        args[1] = "alpharekt.eth";

        voteConsumer.sendRequest(1797, args);

        console2.log("Deployer address:");
        console2.log(msg.sender);
        console2.log("______________________");
        console2.log("Deployed VoteConsumer address:");
        console2.log(address(voteConsumer));

        vm.stopBroadcast();
    }
}
