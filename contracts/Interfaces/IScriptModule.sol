// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

interface IScriptModule {
    function source() external view returns (string memory);
    function buildRequestArgs(string memory id) external view returns (string[] memory args);
}