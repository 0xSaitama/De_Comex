// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {Snapshot} from "../contracts/Modules/Snapshot.sol";

/// @title DeploySnapshotModule
/// @dev Simple deploying script.
/// @author 0xSaitama

contract DeploySnapshotModule is Test {
    Snapshot public snapshot;

    function run() public {
        vm.startBroadcast();

        /// @dev We load inside the script the js file.
        string memory root = vm.projectRoot();
        string memory sourceFilePath = string(
            abi.encodePacked(
                root, "/script/source.js"
            )
        );
        string memory jsScriptSource = vm.readFile(sourceFilePath);
        

        snapshot = new Snapshot("alpharekt.eth", jsScriptSource);

        console2.log("Deployer address:");
        console2.log(msg.sender);
        console2.log("______________________");
        console2.log("Deployed Snapshot module address:");
        console2.log(address(snapshot));

        vm.stopBroadcast();
    }
}
