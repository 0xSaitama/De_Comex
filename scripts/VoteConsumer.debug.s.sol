// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity 0.8.19;

import "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {VoteConsumer} from "../contracts/VoteConsumer.sol";

/// @title DeployVoteConsumer
/// @dev Simple deploying script.
/// @author 0xSaitama

contract DebugVoteConsumer is Test {
    VoteConsumer public voteConsumer;
     address payable public constant deployedVoteConsumer = payable(address(0x78855F78F1669D30a2B766b038D203266f7Adc3D));

    function run() public {
        vm.startBroadcast();

        voteConsumer = VoteConsumer(deployedVoteConsumer);
        
        //voteConsumer.setGasLimit(100_000);
        bytes32 txHash = voteConsumer.requestIdToTxHash(bytes32(0x1cb9a1e7e5f6a3fc89d16d0486c98ae3b387274cbd55dc4c80fee5f2c73ed9db));

        console2.logBytes32(txHash);

        bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", address(0xDDf86597aFF5c826643BCed8eF0b84b10a2847aB), 1_000_000);

        VoteConsumer.Transaction[] memory tx = new VoteConsumer.Transaction[](1);
        
        tx[0] = VoteConsumer.Transaction({
            target: address(0x36053e79F719C3a09A4D84d11A273aA3B4874d04),
            data: data,
            value: 0
        });

        bytes32 hash = keccak256(abi.encode(tx));

        console2.logBytes32(hash);
        assertEq(hash, txHash);
        assertTrue(hash != txHash);
        vm.stopBroadcast();
    }
}
