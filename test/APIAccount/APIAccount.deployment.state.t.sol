// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import {APIAccount} from "./../../contracts/APIAccount.sol";
import "forge-std/Test.sol";

contract APIAccountDeploymentStateTest is Test {
    using stdStorage for StdStorage;

    /*//////////////////////////////////////////////////////////////
                        During Deployment                   
    //////////////////////////////////////////////////////////////*/

    /// @dev Should not deploy the contract with a zero address as the initial owner.
    function testFuzz_deployment_withRevert_givenTreasuryAddressIsZeroAddress()
        public
    {
        vm.expectRevert();
        new APIAccount(address(0));
    }

    /// @dev Should allow the deployment of the contract with a non-zero address as the treasury address.
    function testFuzz_deployment_successful(address initialOwner) public {
        vm.assume(initialOwner != address(0));
        APIAccount apiAccount = new APIAccount(initialOwner);
        assertTrue(address(apiAccount).code.length != 0);
    }
}
