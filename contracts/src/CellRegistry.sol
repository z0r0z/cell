// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {CellAttestation as A} from "./CellAttestation.sol";

/// @title CellRegistry
/// @notice Gate an action on "a CELL device says a human bled for this".
///
/// The verifier library proves a record is genuine. This adds the three things
/// a contract has to hold itself, none of which are in the record:
///
///   which key belongs to whom      a record signed by a stranger's device is
///                                  genuine and worthless
///   the highest counter seen       otherwise yesterday's blood attestation
///                                  authorises today's action
///   which firmware is acceptable   the claim rests on the firmware, so a
///                                  build you do not recognise is not a claim
///
/// The digest the device signed must commit to this chain, this contract, and
/// the claimant. Otherwise a record redeemed here is replayable on a fork, on
/// another deployment, or by someone else.
contract CellRegistry {
    struct Signer {
        bytes32 pubkey;      // x-only attestation key
        uint64  lastCounter; // strictly increasing, per key
        bool    registered;
        uint64  lastSeen;    // when a living human was last proven present
    }

    address public admin;
    uint8   public requiredTier = A.TIER_BLOOD;

    /// @notice Proof of life is a pulse, not a drop. Fifteen seconds and no
    /// consumable, because a beacon nobody can be bothered to produce is a
    /// dead-man switch that fires on the living.
    uint8   public beaconTier = A.TIER_TOUCH;

    /// @dev Fixed, not configurable. The epoch index is computed off chain by
    /// a device with no clock, so the period has to be a number both sides
    /// already know. Changing it would move every past and future period.
    uint64  public constant EPOCH_SECONDS = 30 days;

    /// @dev keccak256("CELL/beacon-v1"). Domain separation from every other
    /// purpose word: a beacon must not redeem as an allowlist entry, and an
    /// allowlist entry must not read as proof of life.
    bytes32 public constant BEACON_TAG =
        0x1209952fe8f5fbf2317b2ccbee619112556d6d6da583fe56b957dbd0906767d9;

    /// @dev keccak256("CELL/redeem-v1"). The other half of that separation,
    /// and the half that was missing. `redeem` takes an ARBITRARY purpose word
    /// from its caller, so without a tag of its own a caller could simply pass
    /// `beaconPurpose(epoch)` and redeem a proof of life -- fifteen seconds of
    /// a fingertip -- as an allowlist entry that is supposed to cost a drop of
    /// blood. Tagging makes the two namespaces disjoint by construction.
    bytes32 public constant REDEEM_TAG =
        0x439f3e546440388c849fc333d144961e4f120e8b1febe763de650ad601a2d8b7;

    mapping(address => Signer) public signers;
    mapping(bytes32 => bool)   public allowedFirmware;
    mapping(bytes32 => bool)   public allowedCalibration;
    /// @dev Keyed by purpose as well as by address. One bool per address
    /// cannot say WHICH round admitted somebody, so a record redeemed for
    /// round 1 read as admission to round 2 as well.
    mapping(address => mapping(bytes32 => bool)) public allowlisted;

    event Registered(address indexed who, bytes32 pubkey);
    event Admitted(address indexed who, bytes32 indexed purpose, uint8 tier,
                   uint64 counter);
    event Alive(address indexed who, uint64 indexed epoch, uint8 tier, uint64 counter);

    error NotAdmin();
    error AlreadyRegistered();
    error NotRegistered();
    error BadSignature();
    error WrongDigest();
    error CounterNotFresh();
    error FirmwareNotAllowed();
    error CalibrationNotAllowed();
    error TierTooLow();
    error EpochNotCurrent();
    error BadTier();

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    function allowFirmware(bytes32 h, bool ok) external onlyAdmin { allowedFirmware[h] = ok; }
    function allowCalibration(bytes32 h, bool ok) external onlyAdmin { allowedCalibration[h] = ok; }
    /// @dev Bounded on purpose. `setRequiredTier(0)` is not a loud mistake --
    /// `r.tier < 0` is never true, so it silently removes the tier gate
    /// altogether. `setBeaconTier(3)` is worse: no record can reach it, every
    /// heartbeat reverts, and every CellDormancy reading this registry arms
    /// itself against an owner who is alive and beaconing.
    function setRequiredTier(uint8 t) external onlyAdmin {
        if (t != A.TIER_TOUCH && t != A.TIER_BLOOD) revert BadTier();
        requiredTier = t;
    }

    function setBeaconTier(uint8 t) external onlyAdmin {
        if (t != A.TIER_TOUCH && t != A.TIER_BLOOD) revert BadTier();
        beaconTier = t;
    }

    /// @notice Record a device's attestation key, once, the way you record an
    /// xpub. Rotation is deliberately absent: the key is generated in the
    /// secure element at provisioning and never leaves it, so a request to
    /// change it is a request to trust a different device.
    function register(bytes32 pubkey) external {
        if (signers[msg.sender].registered) revert AlreadyRegistered();
        // lastSeen starts now. A device that registers and never beacons is
        // dormant from registration, not dormant from the epoch.
        signers[msg.sender] = Signer({
            pubkey: pubkey, lastCounter: 0, registered: true,
            lastSeen: uint64(block.timestamp)
        });
        emit Registered(msg.sender, pubkey);
    }

    /// @notice The digest a device must sign for `claimant` to redeem here.
    /// @dev Commits to chain, contract and claimant, so the same record cannot
    /// be replayed on another chain, another deployment, or by another account.
    function actionDigest(address claimant, bytes32 purpose) public view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(this), claimant, purpose));
    }

    /// @notice The purpose word an allowlist record is bound to. Tagged, so
    /// that no caller-chosen `purpose` can be spelled to collide with
    /// `beaconPurpose`. firmware/beacon.py builds the same thing.
    function redeemPurpose(bytes32 purpose) public pure returns (bytes32) {
        return keccak256(abi.encode(REDEEM_TAG, purpose));
    }

    /// @notice Verify a record and admit the caller for one purpose.
    function redeem(bytes calldata record, bytes32 purpose) external {
        Signer storage sg = signers[msg.sender];
        if (!sg.registered) revert NotRegistered();

        bytes32 want = actionDigest(msg.sender, redeemPurpose(purpose));
        (bool ok, A.Record memory r) = A.check(record, sg.pubkey, want);
        if (!ok) {
            // Separate the two so a caller can tell a forged signature from a
            // record that is genuine but bound to something else.
            if (A.parse(record).sighash != want) revert WrongDigest();
            revert BadSignature();
        }
        if (r.tier < requiredTier) revert TierTooLow();
        if (r.counter <= sg.lastCounter) revert CounterNotFresh();
        if (!allowedFirmware[r.fwHash]) revert FirmwareNotAllowed();
        if (!allowedCalibration[r.calHash]) revert CalibrationNotAllowed();

        sg.lastCounter = r.counter;
        allowlisted[msg.sender][purpose] = true;
        emit Admitted(msg.sender, purpose, r.tier, r.counter);
    }

    // ----------------------------------------------------------------------
    // Proof of life
    //
    // A dead-man switch that keys off signing activity cannot tell "this key
    // moved" from "this person is alive". A stolen key resets the clock and a
    // careful owner who does not spend for a year looks dead. The touch gate
    // measures a body, so the two can be separated -- see firmware/beacon.py.
    // ----------------------------------------------------------------------

    /// @notice The period index now. The device is told this and shows the
    /// owner a date; the chain is what enforces it.
    function currentEpoch() public view returns (uint64) {
        return uint64(block.timestamp / EPOCH_SECONDS);
    }

    /// @notice The purpose word for one period, as firmware/beacon.py builds it.
    function beaconPurpose(uint64 epoch) public pure returns (bytes32) {
        return keccak256(abi.encode(BEACON_TAG, uint256(epoch)));
    }

    /// @notice The digest a device must sign to prove `claimant` was alive in
    /// `epoch`.
    function beaconDigest(address claimant, uint64 epoch) public view returns (bytes32) {
        return actionDigest(claimant, beaconPurpose(epoch));
    }

    /// @notice Record that a living human was here, in this period.
    /// @dev The epoch must be the CURRENT one. That is the whole defence
    /// against harvesting: a beacon signed for a future period cannot be
    /// submitted early, and it cannot be submitted late either. A companion
    /// that wants to keep a dead owner alive has to have obtained one
    /// separately gated signature per period, each showing the owner a date
    /// that was not today.
    function heartbeat(bytes calldata record, uint64 epoch) external {
        Signer storage sg = signers[msg.sender];
        if (!sg.registered) revert NotRegistered();
        if (epoch != currentEpoch()) revert EpochNotCurrent();

        bytes32 want = beaconDigest(msg.sender, epoch);
        (bool ok, A.Record memory r) = A.check(record, sg.pubkey, want);
        if (!ok) {
            if (A.parse(record).sighash != want) revert WrongDigest();
            revert BadSignature();
        }
        if (r.tier < beaconTier) revert TierTooLow();
        if (r.counter <= sg.lastCounter) revert CounterNotFresh();
        if (!allowedFirmware[r.fwHash]) revert FirmwareNotAllowed();
        if (!allowedCalibration[r.calHash]) revert CalibrationNotAllowed();

        sg.lastCounter = r.counter;
        sg.lastSeen = uint64(block.timestamp);
        emit Alive(msg.sender, epoch, r.tier, r.counter);
    }

    /// @notice When `who` last proved they were alive. Registration counts.
    function lastSeen(address who) external view returns (uint64) {
        if (!signers[who].registered) revert NotRegistered();
        return signers[who].lastSeen;
    }

    /// @notice How long `who` has been silent, in seconds.
    function dormantFor(address who) external view returns (uint64) {
        if (!signers[who].registered) revert NotRegistered();
        return uint64(block.timestamp) - signers[who].lastSeen;
    }
}
