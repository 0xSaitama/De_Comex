// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title EIP712Context

abstract contract EIP712Context {
    /// @dev Error when signature verification fails.
    error InvalidSignature();

    struct EIP712Domain {
        string name;
        string version;
        uint256 chainId;
        address verifyingContract;
    }

    string internal constant EIP191_HEADER = "\x19\x01";

    /// @dev keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 constant EIP712DOMAIN_TYPEHASH =
        0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    bytes32 public immutable DOMAIN_SEPARATOR;
    uint256 public immutable CHAIN_ID;

    constructor() {
        /// @dev We cache the chainId found during deployment as well as the DomainSeparator unique to this ID.
        CHAIN_ID = _getChainId();
        DOMAIN_SEPARATOR = _buildDomainSeparator(
            EIP712Domain({
                name: "APIAccount",
                version: "1",
                chainId: _getChainId(),
                verifyingContract: address(this)
            })
        );
    }

    /// @dev Get the Chain Id where the contract is deployed
    /// @return chainId current ChainId
    function _getChainId() internal view returns (uint256 chainId) {
        chainId = block.chainid;
    }

    /// @dev Get the domain separator of the contract.
    /// @return bytes32 hashed domain separator
    /// @notice If the chainId hasn't changed since deployment, we return the cached value, otherwise, we recompute the `DOMAIN_SEPARATOR` value with the new chainId.
    function _getDomainSeparator() internal view returns (bytes32) {
        return _getChainId() == CHAIN_ID
            ? DOMAIN_SEPARATOR
            : _buildDomainSeparator(
                EIP712Domain({
                    name: "APIAccount",
                    version: "1",
                    chainId: _getChainId(),
                    verifyingContract: address(this)
                })
            );
    }

    /// @dev Hash the domain of the contract by following the EIP-712 typehashing.
    /// @param eip712Domain - Data of the contract domain.
    /// @return bytes32 - Hashed domain.
    function _buildDomainSeparator(EIP712Domain memory eip712Domain)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                EIP712DOMAIN_TYPEHASH,
                keccak256(bytes(eip712Domain.name)),
                keccak256(bytes(eip712Domain.version)),
                eip712Domain.chainId,
                eip712Domain.verifyingContract
            )
        );
    }
}
