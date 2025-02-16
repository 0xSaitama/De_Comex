// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import "forge-std/Test.sol";
import {APIAccount} from "../../contracts/APIAccount.sol";
import {BatchVerifier} from "../../contracts/BatchVerifier.sol";
import {InitAPIAccountHarness} from "../initState/InitAPIAccountHarness.sol";

contract APIAccountExecutionStateTest is Test, InitAPIAccountHarness {
    using stdStorage for StdStorage;

    /*//////////////////////////////////////////////////////////////
                    executeTransactionBatch_F45264C Method                   
    //////////////////////////////////////////////////////////////*/

    /// @dev Should not execute a transaction batch if the request ID is unknown.
    function testFuzz_executeTransactionBatch_F45264C_func_withRevert_WrongBatchHash(
        bytes32 requestId,
        APIAccount.Transaction[] calldata transactions,
        uint256 deadline
    ) public {
        vm.assume(deadline > block.timestamp);
    
        vm.expectRevert(APIAccount.WrongBatchHash.selector);
        apiAccountHarness.executeTransactionBatch_F45264C(requestId, transactions, deadline);
    }

    /// @dev Should not execute a transaction batch if the deadline has expired.
    function testFuzz_executeTransactionBatch_F45264C_func_withRevert_RequestExpired(
        bytes32 requestId,
        APIAccount.Transaction[] calldata transactions,
        uint256 deadline
    ) public {
        vm.assume(deadline < block.timestamp);
    
        vm.expectRevert(APIAccount.RequestExpired.selector);
        apiAccountHarness.executeTransactionBatch_F45264C(requestId, transactions, deadline);
    }

    /// @dev Should not execute a transaction batch if it is already executed.
    function testFuzz_executeTransactionBatch_F45264C_func_withRevert_RequestAlreadyExecuted(
        bytes32 requestId,
        uint256 deadline
    ) public {
        vm.assume(deadline > block.timestamp);

        APIAccount.Transaction[] memory transactions = new APIAccount.Transaction[](1);
        transactions[0] = BatchVerifier.Transaction({
            target: address(mockERC20),
            value: 0,
            data: abi.encodeWithSelector(mockERC20.faucet.selector, 1 ether)
        });

        bytes32 batchHash = apiAccountHarness.hashTransactionBatchHelper(transactions, deadline);
        apiAccountHarness.setRequestIdToTxHash(requestId, batchHash);

        apiAccountHarness.executeTransactionBatch_F45264C(requestId, transactions, deadline);

        uint256 expectedBalance = mockERC20.balanceOf(address(apiAccountHarness));
        assertEq(expectedBalance, 1 ether);
        assertTrue(apiAccountHarness.getCompletedRequest(requestId));

        vm.expectRevert(APIAccount.RequestAlreadyExecuted.selector);
        apiAccountHarness.executeTransactionBatch_F45264C(requestId, transactions, deadline);
    }

    /// @dev Should execute a transaction batch of ERC20 transfers.
    function testFuzz_executeTransactionBatch_F45264C_func(
        bytes32 requestId,
        address receiver,
        uint256 amount,
        uint256 deadline
    ) public {
        vm.assume(deadline > block.timestamp);
   
        APIAccount.Transaction[] memory transactions = new APIAccount.Transaction[](2);
        transactions[0] = BatchVerifier.Transaction({
            target: address(mockERC20),
            value: 0,
            data: abi.encodeWithSelector(mockERC20.faucet.selector, amount)
        });
         transactions[1] = BatchVerifier.Transaction({
            target: address(mockERC20),
            value: 0,
            data: abi.encodeWithSelector(mockERC20.transfer.selector, receiver,  amount)
        });

        bytes32 batchHash = apiAccountHarness.hashTransactionBatchHelper(transactions, deadline);
        apiAccountHarness.setRequestIdToTxHash(requestId, batchHash);

        apiAccountHarness.executeTransactionBatch_F45264C(requestId, transactions, deadline);

        uint256 apiAccountBalance = mockERC20.balanceOf(address(apiAccountHarness));
        uint256 receiverBalance = mockERC20.balanceOf(address(receiver));
        assertEq(apiAccountBalance, 0);
        assertEq(receiverBalance, amount);
        assertTrue(apiAccountHarness.getCompletedRequest(requestId));
    }

}
