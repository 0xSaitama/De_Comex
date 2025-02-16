// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {APIAccount} from "../contracts/APIAccount.sol";
import {BatchVerifier} from "../contracts/BatchVerifier.sol";

/// @title DeployAPIAccount
/// @dev Execute request script.
/// @author 0xSaitama

contract ExecuteAPIAccount is Test {
    APIAccount public apiAccount;
    address payable public constant deployedAPIAccount = payable(address(0xA53Ba7B375b82C18475eC2658Bd9963f093D3C48));
    bytes32 requestId = bytes32(0x7c2288973d37b97786aa24d3ae9033ffc6f3dab358de543ebe242844a68988b4);

    function run() public {
        vm.startBroadcast();

        apiAccount = APIAccount(deployedAPIAccount);
        bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", address(0xDDf86597aFF5c826643BCed8eF0b84b10a2847aB), 1_000_000);
        BatchVerifier.Transaction[] memory transactions = new BatchVerifier.Transaction[](1);
         transactions[0] = BatchVerifier.Transaction({
            target: address(0x36053e79F719C3a09A4D84d11A273aA3B4774d04),
            data: data,
            value: 0
        });
        apiAccount.executeTransactionBatch_F45264C(requestId, transactions);
        

        vm.stopBroadcast();
    }
}
