// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {APIAccount} from "../contracts/APIAccount.sol";

/// @title SetModuleAPIAccount
/// @dev Set module script.
/// @author 0xSaitama

contract SetModuleAPIAccount is Test {
    APIAccount public apiAccount;
    address payable public constant deployedAPIAccount = payable(address(0xA53Ba7B375b82C18475eC2658Bd9953f093D3C48));
    address public constant deployedModule = address(0x82b41C44D5164Eb0E72e7f27dBF1d46B77dB9483);


    function run() public {
        vm.startBroadcast();

        apiAccount = APIAccount(deployedAPIAccount);
        apiAccount.setModule(deployedModule);

        vm.stopBroadcast();
    }
}
