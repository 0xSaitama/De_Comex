// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import "forge-std/Test.sol";
import {InitAPIAccount} from "../initState/InitAPIAccount.sol";

contract APIAccountOwnerStateTest is Test, InitAPIAccount {
    using stdStorage for StdStorage;

    /*//////////////////////////////////////////////////////////////
                        setModule Method                   
    //////////////////////////////////////////////////////////////*/

    /// @dev Should not allow a non-owner to set the js source code module involved in oracle request.
    function testFuzz_setModule_func_withRevert_callerIsNotOwner(
        address caller,
        address module
    ) public {
        vm.assume(caller != initialOwner);
        hoax(caller);
        vm.expectRevert(bytes("Only callable by owner"));
        apiAccount.setModule(module);
    }

    /// @dev Should allow the owner to set the js source code module involved in oracle request.
    function test_setModule_func_callerIsOwner(address module) public {
        assertEq(apiAccount.scriptModule(), address(0));
        hoax(initialOwner);
        apiAccount.setModule(module);
        assertEq(apiAccount.scriptModule(), module);
    }

    /*//////////////////////////////////////////////////////////////
                        setGaslimitPerTx Method                   
    //////////////////////////////////////////////////////////////*/

    /// @dev Should not allow a non-owner to set the gas limit allowed per transaction.
    function testFuzz_setGaslimitPerTx_func_withRevert_callerIsNotOwner(
        address caller
    ) public {
        vm.assume(caller != initialOwner);
        hoax(caller);
        vm.expectRevert(bytes("Only callable by owner"));
        apiAccount.setGaslimitPerTx(0);
    }

    /// @dev Should allow the owner to set the gas limit allowed per transaction.
    function testFuzz_setGaslimitPerTx_func_callerIsOwner(
        uint32 newGaslimitPerTx
    ) public {
        assertEq(apiAccount.gasLimitPerTx(), 300_000);

        hoax(initialOwner);
        apiAccount.setGaslimitPerTx(newGaslimitPerTx);

        assertEq(apiAccount.gasLimitPerTx(), newGaslimitPerTx);
    }

    /*//////////////////////////////////////////////////////////////
                    setGaslimitPerBatch Method                   
    //////////////////////////////////////////////////////////////*/

    /// @dev Should not allow a non-owner to set the gas limit allowed per transaction batch.
    function testFuzz_setGaslimitPerBatch_func_withRevert_callerIsNotOwner(
        address caller
    ) public {
        vm.assume(caller != initialOwner);
        hoax(caller);
        vm.expectRevert(bytes("Only callable by owner"));
        apiAccount.setGaslimitPerBatch(0);
    }

    /// @dev Should allow the owner to set the gas limit allowed per transaction batch.
    function testFuzz_setGaslimitPerBatch_func_callerIsOwner(
        uint32 newGaslimitPerBatch
    ) public {
        assertEq(apiAccount.gasLimitPerBatch(), 30_000_000);

        hoax(initialOwner);
        apiAccount.setGaslimitPerBatch(newGaslimitPerBatch);

        assertEq(apiAccount.gasLimitPerBatch(), newGaslimitPerBatch);
    }

    /*//////////////////////////////////////////////////////////////
                    setCallBackGasLimit Method                   
    //////////////////////////////////////////////////////////////*/

    /// @dev Should not allow a non-owner to set the callback gas limit allowed.
    function testFuzz_setCallBackGasLimit_func_withRevert_callerIsNotOwner(
        address caller
    ) public {
        vm.assume(caller != initialOwner);
        hoax(caller);
        vm.expectRevert(bytes("Only callable by owner"));
        apiAccount.setCallBackGasLimit(0);
    }

    /// @dev Should allow the owner to set the callback gas limit allowed.
    function testFuzz_setCallBackGasLimit_func_callerIsOwner(
        uint32 newCallBackGasLimit
    ) public {
        assertEq(apiAccount.callBackGasLimit(), 300_000);

        hoax(initialOwner);
        apiAccount.setCallBackGasLimit(newCallBackGasLimit);

        assertEq(apiAccount.callBackGasLimit(), newCallBackGasLimit);
    }
}
