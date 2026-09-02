// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {CellAttestation as A} from "../src/CellAttestation.sol";

/// Vectors come from firmware/attest.py, which is itself checked against the
/// published BIP-340 test vectors. So a pass here means the Solidity agrees
/// with the device, and the device agrees with the standard.
contract CellAttestationTest is Test {
    bytes  record;
    bytes  touchRecord;
    bytes32 pubkey;
    bytes32 sighash;

    function setUp() public {
        string memory j = vm.readFile("test/vectors.json");
        record      = vm.parseJsonBytes(j, ".record");
        touchRecord = vm.parseJsonBytes(j, ".touchRecord");
        pubkey      = vm.parseJsonBytes32(j, ".pubkey");
        sighash     = vm.parseJsonBytes32(j, ".sighash");
    }

    function _check(bytes memory b) internal view returns (bool ok, A.Record memory r) {
        return this.checkExt(b, pubkey, sighash);
    }

    function checkExt(bytes calldata b, bytes32 pk, bytes32 sh)
        external view returns (bool, A.Record memory)
    { return A.check(b, pk, sh); }

    function test_AcceptsGenuineRecord() public view {
        (bool ok, A.Record memory r) = _check(record);
        assertTrue(ok, "signature must verify");
        assertEq(r.tier, A.TIER_BLOOD);
        assertEq(r.counter, 7);
        assertEq(r.pubkey, pubkey);
        assertEq(r.sighash, sighash);
    }

    function test_ParsesTouchTier() public view {
        (bool ok, A.Record memory r) = _check(touchRecord);
        assertTrue(ok);
        assertEq(r.tier, A.TIER_TOUCH);
    }

    /// A record lifted onto a different action must fail. Without the sighash
    /// binding, one blood attestation would authorise anything.
    function test_RejectsWrongSighash() public view {
        (bool ok, ) = this.checkExt(record, pubkey, keccak256("some other action"));
        assertFalse(ok);
    }

    function test_RejectsWrongPubkey() public view {
        (bool ok, ) = this.checkExt(record, bytes32(uint256(1)), sighash);
        assertFalse(ok);
    }

    /// Flipping any byte of the body changes the digest, so the signature
    /// must stop verifying. Covers every field at once.
    function test_RejectsTamperedBody() public view {
        // Every byte, not every seventh. The stride skipped 6 in 7 of the
        // body, and its guard was both dead (i is never 4 or 5 on a stride of
        // 7) and placed AFTER the flip it was meant to skip.
        for (uint256 i = 0; i < A.RECORD_LEN; i++) {
            if (i < 6) continue;        // magic/version/tier revert, tested below
            bytes memory b = record;
            b[i] = bytes1(uint8(b[i]) ^ 0x01);
            (bool ok, ) = this.checkExt(b, pubkey, sighash);
            assertFalse(ok, "tampered body must not verify");
        }
    }

    function test_RejectsTamperedSignature() public view {
        bytes memory b = record;
        b[200] = bytes1(uint8(b[200]) ^ 0x01);
        (bool ok, ) = this.checkExt(b, pubkey, sighash);
        assertFalse(ok);
    }

    function test_RevertsOnMalformed() public {
        bytes memory short_ = new bytes(237);
        vm.expectRevert(A.BadLength.selector);
        this.checkExt(short_, pubkey, sighash);

        bytes memory badMagic = record;
        badMagic[0] = 0x00;
        vm.expectRevert(A.BadMagic.selector);
        this.checkExt(badMagic, pubkey, sighash);

        bytes memory badVer = record;
        badVer[4] = 0x09;
        vm.expectRevert(A.BadVersion.selector);
        this.checkExt(badVer, pubkey, sighash);

        bytes memory badTier = record;
        badTier[5] = 0x07;
        vm.expectRevert(A.BadTier.selector);
        this.checkExt(badTier, pubkey, sighash);
    }

    /// An all-zero signature must not recover to address(0) and pass.
    function test_RejectsZeroSignature() public view {
        bytes memory b = record;
        for (uint256 i = A.RECORD_LEN; i < A.PACKED_LEN; i++) b[i] = 0;
        (bool ok, ) = this.checkExt(b, pubkey, sighash);
        assertFalse(ok);
    }

    /// An x-coordinate not on the curve must be rejected by the lift, not
    /// silently accepted.
    function test_RejectsOffCurveR() public view {
        bytes memory b = record;
        for (uint256 i = A.RECORD_LEN; i < A.RECORD_LEN + 32; i++) b[i] = 0xff;
        (bool ok, ) = this.checkExt(b, pubkey, sighash);
        assertFalse(ok);
    }

    function test_GasCost() public {
        uint256 g = gasleft();
        this.checkExt(record, pubkey, sighash);
        emit log_named_uint("verify gas (incl. calldata + external call)", g - gasleft());
    }
}
