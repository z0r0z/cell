// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {CellRegistry} from "../src/CellRegistry.sol";
import {CellAttestation as A} from "../src/CellAttestation.sol";

/// The registry is tested against records generated for its own actionDigest,
/// produced by firmware/attest.py in test/gen_registry_vectors.py.
contract CellRegistryTest is Test {
    CellRegistry reg;
    bytes   rec;        // blood, counter 7, bound to (chain, reg, user, purpose)
    bytes   recLater;   // blood, counter 9, same binding
    bytes   recTouch;   // touch tier, counter 11
    bytes   recOther;   // blood, bound to a different claimant
    bytes32 pubkey;
    bytes32 fwHash;
    bytes32 calHash;
    bytes32 purpose;
    address user;

    // Deployed from a fixed address at nonce 0, so the address is known before
    // the vectors are generated. actionDigest commits to it, which is what
    // stops a record being replayed against another deployment.
    address constant DEPLOYER = 0x00000000000000000000000000000000000000D1;

    function setUp() public {
        vm.prank(DEPLOYER);
        reg = new CellRegistry();

        string memory j = vm.readFile("test/registry_vectors.json");
        assertEq(address(reg), vm.parseJsonAddress(j, ".registry"),
                 "vectors were generated for a different registry address");

        rec      = vm.parseJsonBytes(j, ".record");
        recLater = vm.parseJsonBytes(j, ".recordLater");
        recTouch = vm.parseJsonBytes(j, ".recordTouch");
        recOther = vm.parseJsonBytes(j, ".recordOtherClaimant");
        pubkey   = vm.parseJsonBytes32(j, ".pubkey");
        fwHash   = vm.parseJsonBytes32(j, ".fwHash");
        calHash  = vm.parseJsonBytes32(j, ".calHash");
        purpose  = vm.parseJsonBytes32(j, ".purpose");
        user     = vm.parseJsonAddress(j, ".user");

        vm.startPrank(DEPLOYER);
        reg.allowFirmware(fwHash, true);
        reg.allowCalibration(calHash, true);
        vm.stopPrank();
        vm.prank(user);
        reg.register(pubkey);
    }

    function test_AdmitsBloodAttestation() public {
        vm.prank(user);
        reg.redeem(rec, purpose);
        assertTrue(reg.allowlisted(user));
        (, uint64 last, , ) = reg.signers(user);
        assertEq(last, 7);
    }

    /// The whole point of the counter: yesterday's blood must not authorise
    /// today's action.
    function test_RejectsReplay() public {
        vm.startPrank(user);
        reg.redeem(rec, purpose);
        vm.expectRevert(CellRegistry.CounterNotFresh.selector);
        reg.redeem(rec, purpose);
        vm.stopPrank();
    }

    function test_AcceptsHigherCounterAfter() public {
        vm.startPrank(user);
        reg.redeem(rec, purpose);
        reg.redeem(recLater, purpose);
        vm.stopPrank();
        (, uint64 last, , ) = reg.signers(user);
        assertEq(last, 9);
    }

    function test_RejectsTouchWhenBloodRequired() public {
        vm.prank(user);
        vm.expectRevert(CellRegistry.TierTooLow.selector);
        reg.redeem(recTouch, purpose);
    }

    /// A genuine record belonging to someone else must not admit the caller.
    function test_RejectsRecordForAnotherClaimant() public {
        vm.prank(user);
        vm.expectRevert(CellRegistry.WrongDigest.selector);
        reg.redeem(recOther, purpose);
    }

    function test_RejectsUnknownFirmware() public {
        vm.prank(DEPLOYER);
        reg.allowFirmware(fwHash, false);
        vm.prank(user);
        vm.expectRevert(CellRegistry.FirmwareNotAllowed.selector);
        reg.redeem(rec, purpose);
    }

    function test_RejectsUnknownCalibration() public {
        vm.prank(DEPLOYER);
        reg.allowCalibration(calHash, false);
        vm.prank(user);
        vm.expectRevert(CellRegistry.CalibrationNotAllowed.selector);
        reg.redeem(rec, purpose);
    }

    function test_RejectsUnregisteredSigner() public {
        address stranger = address(0xBEEF);
        vm.prank(stranger);
        vm.expectRevert(CellRegistry.NotRegistered.selector);
        reg.redeem(rec, purpose);
    }

    function test_GasCost() public {
        vm.prank(user);
        uint256 g = gasleft();
        reg.redeem(rec, purpose);
        emit log_named_uint("redeem gas", g - gasleft());
    }
}
