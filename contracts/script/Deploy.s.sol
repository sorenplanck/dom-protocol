// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ConditionLockERC20V2} from "../src/ConditionLockERC20V2.sol";
import {ConditionLockV2} from "../src/ConditionLockV2.sol";
import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

/// @notice Deploys both lock variants. Used by the local Anvil end-to-end
///         harness and by the Sepolia scripts.
/// @dev Neither contract has a constructor argument, because neither has
///      anything a deployer could be privileged over. The deployer is just the
///      account that paid for the code; it holds no rights afterwards.
///
///      Safety rails:
///      * the target chain id must be declared through `EXPECTED_CHAIN_ID` and
///        must match the connected endpoint, so a misconfigured RPC cannot send
///        a deployment somewhere unintended;
///      * Ethereum mainnet (chain id 1) is rejected outright. It is NOT the
///        general defence, and is not meant to be: the mandatory
///        `EXPECTED_CHAIN_ID` match above already covers every other network,
///        including every other mainnet, because a deployment can only ever
///        reach a chain the operator named explicitly. The chain-id-1 check is
///        a second, unconditional stop on the one destination where a
///        mis-set environment variable would be least recoverable, and this
///        project targets no L1 mainnet at all (spec section 4: no mainnet);
///      * the signing key is supplied by the Foundry wallet flags
///        (`--private-key`, `--keystore`, `--ledger`, ...). It is never read
///        from the environment here, never logged and never persisted.
contract DeployScript is Script {
    error UnexpectedChainId(uint256 expected, uint256 actual);
    error MainnetIsNotATarget();

    function run() external returns (ConditionLockV2 nativeLock, ConditionLockERC20V2 erc20Lock) {
        uint256 expectedChainId = vm.envUint("EXPECTED_CHAIN_ID");
        if (block.chainid == 1) revert MainnetIsNotATarget();
        if (block.chainid != expectedChainId) revert UnexpectedChainId(expectedChainId, block.chainid);

        vm.startBroadcast();
        nativeLock = new ConditionLockV2();
        erc20Lock = new ConditionLockERC20V2();
        vm.stopBroadcast();

        console2.log("chainId", block.chainid);
        console2.log("ConditionLockV2", address(nativeLock));
        console2.log("ConditionLockERC20V2", address(erc20Lock));
    }
}
