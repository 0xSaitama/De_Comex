// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {MockERC20} from "../../contracts/Mocks/MockERC20.sol";

abstract contract InitMockERC20 is Test {
    MockERC20 internal mockERC20;

    function setUpERC20() public virtual {
        mockERC20 = new MockERC20("MockERC20", "M20", 0);
    }
}
