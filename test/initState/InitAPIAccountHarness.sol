// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {APIAccountHarness} from "../utils/APIAccountHarness.sol";
import {InitMockERC20} from "./InitMockERC20.sol";

abstract contract InitAPIAccountHarness is Test, InitMockERC20 {
    APIAccountHarness internal apiAccountHarness;

    address initialOwner = makeAddr("initialOwner");

    function setUp() public virtual {
        apiAccountHarness = new APIAccountHarness(initialOwner);
        setUpERC20();
    }
}
