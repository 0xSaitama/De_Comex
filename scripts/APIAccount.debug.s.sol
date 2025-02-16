// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {APIAccount} from "../contracts/APIAccount.sol";
import {BatchVerifier} from "../contracts/BatchVerifier.sol";
import {APIAccountHarness} from "../test/utils/APIAccountHarness.sol";

/// @title DebugAPIAccount
/// @dev Simple debug script.
/// @author 0xSaitama

contract DebugAPIAccount is Test {
    APIAccount public apiAccount;
    address payable public constant deployedAPIAccount =
        payable(address(0x1));
    uint256 public constant deadline = 1740924560;

    function run() public {
        vm.startBroadcast();

        apiAccount = APIAccount(deployedAPIAccount);

        bytes32 txHash = apiAccount.requestIdToTxHash(
            bytes32(
                0xae246ed02fb6c8d90820f340e446b0d223341276b4241c2c19ec23c34d4400e9
            )
        );

        console2.logBytes32(txHash);

        bytes memory data = abi.encodeWithSignature(
            "transfer(address,uint256)",
            address(0x2),
            1_000_000
        );

        BatchVerifier.Transaction[]
            memory transaction = new BatchVerifier.Transaction[](1);

        transaction[0] = BatchVerifier.Transaction({
            target: address(0x36053e79F719C3a09A4D84d11A273aA3B4874d05),
            data: data,
            value: 0
        });

        APIAccountHarness apiAccountHarness = new APIAccountHarness(msg.sender);

        bytes32 hash = apiAccountHarness.hashTransactionBatchHelper(
            transaction,
            deadline
        );

        console2.logBytes32(hash);
        assertEq(hash, txHash);
        vm.stopBroadcast();
    }
}
