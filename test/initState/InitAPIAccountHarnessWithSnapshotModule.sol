// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {APIAccountHarness} from "../utils/APIAccountHarness.sol";
import {InitMockERC20} from "./InitMockERC20.sol";
import {InitSnapshotModule} from "./InitSnapshotModule.sol";

abstract contract InitAPIAccountHarness is Test, InitMockERC20, InitSnapshotModule {
    APIAccountHarness internal apiAccountHarness;

    address initialOwner = makeAddr("initialOwner");

    function setUp() public virtual override {
        apiAccountHarness = new APIAccountHarness(initialOwner);
        apiAccountHarness.setModule(address(snapshot));
        setUpERC20();
    }
}
