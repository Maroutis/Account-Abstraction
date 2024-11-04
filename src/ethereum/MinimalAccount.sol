// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IAccount, PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/IAccount.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "lib/account-abstraction/contracts/core/Helpers.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";

contract MinimalAccount is IAccount, Ownable {
    // entrypoint --> this contract
    // uint256 ourNonce;

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error MinimalAccount__NotFromEntryPoint();
    error MinimalAccount__NotFromEntryPointOrOwner();
    error MinimalAccount__CallFailed(bytes);

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    IEntryPoint private immutable i_entrypoint;

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier requireFromEntryPoint() {
        if (msg.sender != address(i_entrypoint)) {
            revert MinimalAccount__NotFromEntryPoint();
        }
        _;
    }

    modifier requireFromEntryPointOrOwner(){
        if (msg.sender != address(i_entrypoint) && msg.sender != owner()) {
            revert MinimalAccount__NotFromEntryPointOrOwner();
        }
        _;
    }

    /*//////////////////////////////////////////////////////////////
                               FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    constructor(address entryPoint) Ownable(msg.sender) {
        i_entrypoint = IEntryPoint(entryPoint);
    }

    receive() external payable {} //@note no paymaster, needs to send funds directly to this contract

    /*//////////////////////////////////////////////////////////////
                           EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function execute(address dest, uint256 value, bytes calldata functionData) external requireFromEntryPointOrOwner {
        (bool success, bytes memory result) = dest.call{value: value}(functionData);

        if(!success){
            revert MinimalAccount__CallFailed(result);
        }
    }

    // A signature is valid, if it's the contract owner
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash, // is the hash of all data in userOp
        uint256 missingAccountFunds
    ) external requireFromEntryPoint returns (uint256 validationData) {
        validationData = _validateSignature(userOp, userOpHash); // we need to make sure that the signature is valid for the hash
        // _validateNonce() Actual uniqueness of nonce is managed by the entry point

        // Pay back money to the entry point. missingAccountFunds how much this tx is going to cost. // If you have a paymaster, you can set up the paymaster to pay for this. But we will pay them ourselves
        _payPrefund(missingAccountFunds);
    }

    /*//////////////////////////////////////////////////////////////
                           INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    // EIP-191 version of the signed hash
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        view
        returns (uint256 validationData)
    {
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        address signer = ECDSA.recover(ethSignedMessageHash, userOp.signature);
        return signer == owner() ? SIG_VALIDATION_SUCCESS : SIG_VALIDATION_FAILED;
    }

    function _payPrefund(uint256 missingAccountFunds) internal {
        if (missingAccountFunds != 0) {
            (bool success,) = payable(msg.sender).call{value: missingAccountFunds, gas: type(uint256).max}("");
            success;
        }
    }

    /*//////////////////////////////////////////////////////////////
                                GETTERS
    //////////////////////////////////////////////////////////////*/
    function getEntryPoint() external view returns (address) {
        return address(i_entrypoint);
    }
}
