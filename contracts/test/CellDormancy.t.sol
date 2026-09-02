// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {CellRegistry} from "../src/CellRegistry.sol";
import {CellDormancy} from "../src/CellDormancy.sol";
import {CellAttestation as A} from "../src/CellAttestation.sol";

/// Proof of life, and the switch that reads it.
///
/// The records come from firmware/attest.py through beacon.py, generated in
/// test/gen_registry_vectors.py for this registry's own beaconDigest.
contract CellDormancyTest is Test {
    CellRegistry reg;
    CellDormancy dead;

    bytes   beaconTouch;    // touch tier, counter 21, for EPOCH
    bytes   beaconBlood;    // blood tier, counter 23, for EPOCH
    bytes   beaconNext;     // touch tier, counter 25, for EPOCH + 1
    bytes32 pubkey;
    bytes32 fwHash;
    bytes32 calHash;
    bytes32 beaconTag;
    address user;
    uint64  EPOCH;
    uint64  EPOCH_SECONDS;

    address constant DEPLOYER = 0x00000000000000000000000000000000000000D1;
    address constant HEIR     = 0x00000000000000000000000000000000000000B1;

    uint64 constant DORMANCY  = 180 days;
    uint64 constant CHALLENGE = 30 days;

    function setUp() public {
        vm.prank(DEPLOYER);
        reg = new CellRegistry();

        string memory j = vm.readFile("test/registry_vectors.json");
        assertEq(address(reg), vm.parseJsonAddress(j, ".registry"),
                 "vectors were generated for a different registry address");

        beaconTouch   = vm.parseJsonBytes(j, ".beaconTouch");
        beaconBlood   = vm.parseJsonBytes(j, ".beaconBlood");
        beaconNext    = vm.parseJsonBytes(j, ".beaconNextEpoch");
        pubkey        = vm.parseJsonBytes32(j, ".pubkey");
        fwHash        = vm.parseJsonBytes32(j, ".fwHash");
        calHash       = vm.parseJsonBytes32(j, ".calHash");
        beaconTag     = vm.parseJsonBytes32(j, ".beaconTag");
        user          = vm.parseJsonAddress(j, ".user");
        EPOCH         = uint64(vm.parseJsonUint(j, ".beaconEpoch"));
        EPOCH_SECONDS = uint64(vm.parseJsonUint(j, ".beaconEpochSeconds"));

        vm.startPrank(DEPLOYER);
        reg.allowFirmware(fwHash, true);
        reg.allowCalibration(calHash, true);
        vm.stopPrank();

        // Into the period the vectors were signed for.
        vm.warp(uint256(EPOCH) * EPOCH_SECONDS + 1 days);

        vm.prank(user);
        reg.register(pubkey);

        dead = new CellDormancy(reg, user, HEIR, DORMANCY, CHALLENGE);
    }

    // ---- the period ------------------------------------------------------

    function test_TagMatchesTheFirmware() public view {
        assertEq(reg.BEACON_TAG(), beaconTag,
                 "the tag in the contract is not the one beacon.py signs under");
        assertEq(uint256(reg.EPOCH_SECONDS()), uint256(EPOCH_SECONDS));
    }

    function test_CurrentEpochIsTheSignedOne() public view {
        assertEq(uint256(reg.currentEpoch()), uint256(EPOCH));
    }

    // ---- the beacon ------------------------------------------------------

    function test_TouchBeaconIsEnough() public {
        vm.prank(user);
        reg.heartbeat(beaconTouch, EPOCH);
        assertEq(uint256(reg.lastSeen(user)), block.timestamp);
        assertEq(uint256(reg.dormantFor(user)), 0);
    }

    function test_BloodBeaconAlsoWorks() public {
        vm.prank(user);
        reg.heartbeat(beaconBlood, EPOCH);
        assertEq(uint256(reg.dormantFor(user)), 0);
    }

    function test_RejectsABeaconForAnotherPeriod() public {
        vm.prank(user);
        vm.expectRevert(CellRegistry.EpochNotCurrent.selector);
        reg.heartbeat(beaconNext, EPOCH + 1);
    }

    /// A harvested beacon cannot be spent early, and it cannot be spent late.
    /// This is the whole bound on a companion that collected future periods.
    function test_AHarvestedBeaconIsOnlyGoodInItsOwnPeriod() public {
        vm.warp(uint256(EPOCH + 1) * EPOCH_SECONDS + 1 days);
        vm.prank(user);
        reg.heartbeat(beaconNext, EPOCH + 1);           // its period arrived
        assertEq(uint256(reg.dormantFor(user)), 0);

        vm.warp(uint256(EPOCH + 2) * EPOCH_SECONDS + 1 days);
        vm.prank(user);
        vm.expectRevert(CellRegistry.EpochNotCurrent.selector);
        reg.heartbeat(beaconNext, EPOCH + 1);           // and then it is stale
    }

    function test_RejectsAReplayedCounter() public {
        vm.startPrank(user);
        reg.heartbeat(beaconBlood, EPOCH);              // counter 23
        vm.expectRevert(CellRegistry.CounterNotFresh.selector);
        reg.heartbeat(beaconTouch, EPOCH);              // counter 21
        vm.stopPrank();
    }

    function test_RejectsAnAllowlistRecordAsABeacon() public {
        string memory j = vm.readFile("test/registry_vectors.json");
        bytes memory allowlist = vm.parseJsonBytes(j, ".record");
        vm.prank(user);
        vm.expectRevert(CellRegistry.WrongDigest.selector);
        reg.heartbeat(allowlist, EPOCH);
    }

    function test_RejectsAnUnregisteredSigner() public {
        vm.prank(HEIR);
        vm.expectRevert(CellRegistry.NotRegistered.selector);
        reg.heartbeat(beaconTouch, EPOCH);
    }

    function test_RejectsUnknownFirmware() public {
        vm.prank(DEPLOYER);
        reg.allowFirmware(fwHash, false);
        vm.prank(user);
        vm.expectRevert(CellRegistry.FirmwareNotAllowed.selector);
        reg.heartbeat(beaconTouch, EPOCH);
    }

    function test_ABeaconBelowTheRequiredTierIsRefused() public {
        vm.prank(DEPLOYER);
        reg.setBeaconTier(A.TIER_BLOOD);
        vm.prank(user);
        vm.expectRevert(CellRegistry.TierTooLow.selector);
        reg.heartbeat(beaconTouch, EPOCH);
        vm.prank(user);
        reg.heartbeat(beaconBlood, EPOCH);              // and blood still is
    }

    function test_GasCost() public {
        vm.prank(user);
        uint256 before = gasleft();
        reg.heartbeat(beaconTouch, EPOCH);
        emit log_named_uint("heartbeat gas", before - gasleft());
    }

    // ---- the switch ------------------------------------------------------

    function test_RegistrationStartsTheClock() public view {
        assertEq(uint256(reg.dormantFor(user)), 0);
        assertEq(uint256(dead.silence()), 0);
    }

    function test_CannotClaimWhileTheOwnerIsRecent() public {
        vm.warp(block.timestamp + DORMANCY - 1);
        vm.prank(HEIR);
        vm.expectRevert(CellDormancy.NotDormantYet.selector);
        dead.startClaim();
    }

    function test_OnlyTheBeneficiaryClaims() public {
        vm.warp(block.timestamp + DORMANCY);
        vm.expectRevert(CellDormancy.NotBeneficiary.selector);
        dead.startClaim();
    }

    function test_AClaimDoesNotReleaseOnItsOwn() public {
        vm.warp(block.timestamp + DORMANCY);
        vm.prank(HEIR);
        dead.startClaim();
        assertFalse(dead.released());
        vm.prank(HEIR);
        vm.expectRevert(CellDormancy.StillInChallengeWindow.selector);
        dead.finalize();
    }

    /// The device came out of the drawer. Fifteen seconds of a fingertip
    /// undoes six months of silence.
    function test_OneBeaconCancelsAClaim() public {
        vm.warp(block.timestamp + DORMANCY);
        vm.prank(HEIR);
        dead.startClaim();

        vm.warp(block.timestamp + 1 days);
        uint64 ep = reg.currentEpoch();
        bytes memory late = _beaconFor(ep);
        vm.prank(user);
        reg.heartbeat(late, ep);

        dead.cancelClaim();                             // anybody may call it
        assertEq(uint256(dead.claimStartedAt()), 0);

        vm.warp(block.timestamp + CHALLENGE + 1);
        vm.prank(HEIR);
        vm.expectRevert(CellDormancy.NoClaimOpen.selector);
        dead.finalize();
    }

    /// A beacon in the same block as the claim counts for the owner.
    function test_ATieGoesToTheLiving() public {
        vm.warp(block.timestamp + DORMANCY);
        uint64 ep = reg.currentEpoch();
        vm.prank(HEIR);
        dead.startClaim();
        vm.prank(user);
        reg.heartbeat(_beaconFor(ep), ep);              // same timestamp
        dead.cancelClaim();
        assertEq(uint256(dead.claimStartedAt()), 0);
    }

    function test_CannotCancelWithoutABeacon() public {
        vm.warp(block.timestamp + DORMANCY);
        vm.prank(HEIR);
        dead.startClaim();
        vm.expectRevert(CellDormancy.OwnerIsNotAlive.selector);
        dead.cancelClaim();
    }

    function test_SilenceThroughTheWindowReleases() public {
        vm.warp(block.timestamp + DORMANCY);
        vm.prank(HEIR);
        dead.startClaim();
        vm.warp(block.timestamp + CHALLENGE + 1);
        vm.prank(HEIR);
        dead.finalize();
        assertTrue(dead.released());
    }

    function test_ABeaconInsideTheWindowBlocksFinalize() public {
        vm.warp(block.timestamp + DORMANCY);
        vm.prank(HEIR);
        dead.startClaim();

        vm.warp(block.timestamp + 1 days);
        uint64 ep = reg.currentEpoch();
        vm.prank(user);
        reg.heartbeat(_beaconFor(ep), ep);              // nobody cancels

        vm.warp(block.timestamp + CHALLENGE + 1);
        vm.prank(HEIR);
        vm.expectRevert(CellDormancy.OwnerIsAlive.selector);
        dead.finalize();
    }

    function test_ReleaseIsFinal() public {
        test_SilenceThroughTheWindowReleases();
        vm.prank(HEIR);
        vm.expectRevert(CellDormancy.AlreadyReleased.selector);
        dead.finalize();
        vm.prank(HEIR);
        vm.expectRevert(CellDormancy.AlreadyReleased.selector);
        dead.startClaim();
    }

    /// A beacon is redeemable only inside its own epoch, so an owner who
    /// beacons in every period can still be silent for one second short of two
    /// of them. A floor of one period fires on exactly that owner, and the
    /// old test only ever probed EPOCH_SECONDS - 1, so it never saw it.
    function test_RefusesAPeriodShorterThanTwoBeacons() public {
        vm.expectRevert(CellDormancy.BadConfiguration.selector);
        new CellDormancy(reg, user, HEIR, EPOCH_SECONDS - 1, CHALLENGE);
        vm.expectRevert(CellDormancy.BadConfiguration.selector);
        new CellDormancy(reg, user, HEIR, EPOCH_SECONDS, CHALLENGE);
        vm.expectRevert(CellDormancy.BadConfiguration.selector);
        new CellDormancy(reg, user, HEIR, 2 * EPOCH_SECONDS - 1, CHALLENGE);
        new CellDormancy(reg, user, HEIR, 2 * EPOCH_SECONDS, CHALLENGE);
        vm.expectRevert(CellDormancy.BadConfiguration.selector);
        new CellDormancy(reg, user, user, DORMANCY, CHALLENGE);
        vm.expectRevert(CellDormancy.BadConfiguration.selector);
        new CellDormancy(reg, user, HEIR, DORMANCY, 0);
    }

    /// The pre-generated beacon for one period. The vectors carry nine of
    /// them, one per period from EPOCH, so a test can warp forward without
    /// calling out to a signer.
    function _beaconFor(uint64 epoch) internal view returns (bytes memory) {
        string memory j = vm.readFile("test/registry_vectors.json");
        return vm.parseJsonBytes(
            j, string.concat(".beaconAt[", vm.toString(uint256(epoch - EPOCH)), "]"));
    }
}
