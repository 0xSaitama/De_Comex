// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {APIAccount} from "../../contracts/APIAccount.sol";

abstract contract InitAPIAccount is Test {
    APIAccount internal apiAccount;

    address initialOwner = makeAddr("initialOwner");

    function setUp() public virtual {
        apiAccount = new APIAccount(initialOwner);
    }
}
