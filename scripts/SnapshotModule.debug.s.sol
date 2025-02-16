// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {Snapshot} from "../contracts/Modules/Snapshot.sol";

/// @title DebugSnapshotModule
/// @dev Simple debug script.
/// @author 0xSaitama

contract DebugSnapshotModule is Test {
    Snapshot public snapshot;
    address payable public constant deployedSnapshotModule = payable(address(0x82b41C44D5164Eb0E72e7f27dAF1d46B77dB9483));

    function run() public {
        vm.startBroadcast();

        snapshot = Snapshot(deployedSnapshotModule);
        
        string memory source = snapshot.source();
        console2.log(source);

        vm.stopBroadcast();
    }
}
