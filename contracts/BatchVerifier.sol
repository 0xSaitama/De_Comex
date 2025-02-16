// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712Context} from "./EIP712Context.sol";

abstract contract BatchVerifier is EIP712Context {
    using ECDSA for bytes32;

    struct Transaction {
        address target;
        bytes data;
        uint256 value;
    }

    // Define the type hash for an array of Transaction structs
    bytes32 constant TRANSACTION_ARRAY_TYPEHASH = keccak256(
        "Transaction[](Transaction(address target,bytes data,uint256 value))"
    );
    
    function hashTransactionBatch(
        Transaction[] calldata transactions,
        uint256 deadline
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                EIP191_HEADER,
                _getDomainSeparator(),
                keccak256(
                    abi.encode(
                        TRANSACTION_ARRAY_TYPEHASH,
                        transactions,
                        deadline
                    )
                )
            )
        );
    }
}
