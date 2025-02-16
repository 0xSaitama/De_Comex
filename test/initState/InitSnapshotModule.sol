// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {Snapshot} from "../../contracts/Modules/Snapshot.sol";

abstract contract InitSnapshotModule is Test {
    Snapshot internal snapshot;

    string public source = "source.js";
    string public spaceID = "DNS.eth";

    function setUp() public virtual {
        snapshot = new Snapshot(source, spaceID);
    }
}
