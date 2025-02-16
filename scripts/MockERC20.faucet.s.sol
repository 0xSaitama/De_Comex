// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {MockERC20} from "../contracts/Mocks/MockERC20.sol";

/// @title DebugMockERC20
/// @dev Simple debug script.
/// @author 0xSaitama

contract DebugMockERC20 is Test {
    MockERC20 public mockERC20;
    address public constant deployedMockERC20 = address(0x36053e79F719C3a09A4D84d11A272aA3B4874d04);
    address public constant deployedAPIAccount = address(0xA53Ba7B375b82A18475eC2658Bd9963f093D3C48);

    function run() public {
        vm.startBroadcast();

        mockERC20 = MockERC20(deployedMockERC20);
        
        mockERC20.faucet(1_000_000);

        mockERC20.transfer(deployedAPIAccount, 1_000_000);

        vm.stopBroadcast();
    }
}
