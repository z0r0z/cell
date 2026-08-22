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
    }

    address public admin;
    uint8   public requiredTier = A.TIER_BLOOD;

    mapping(address => Signer) public signers;
    mapping(bytes32 => bool)   public allowedFirmware;
    mapping(bytes32 => bool)   public allowedCalibration;
    mapping(address => bool)   public allowlisted;

    event Registered(address indexed who, bytes32 pubkey);
    event Admitted(address indexed who, uint8 tier, uint64 counter);

    error NotAdmin();
    error AlreadyRegistered();
    error NotRegistered();
    error BadSignature();
    error WrongDigest();
    error CounterNotFresh();
    error FirmwareNotAllowed();
    error CalibrationNotAllowed();
    error TierTooLow();

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    function allowFirmware(bytes32 h, bool ok) external onlyAdmin { allowedFirmware[h] = ok; }
    function allowCalibration(bytes32 h, bool ok) external onlyAdmin { allowedCalibration[h] = ok; }
    function setRequiredTier(uint8 t) external onlyAdmin { requiredTier = t; }

    /// @notice Record a device's attestation key, once, the way you record an
    /// xpub. Rotation is deliberately absent: the key is generated in the
    /// secure element at provisioning and never leaves it, so a request to
    /// change it is a request to trust a different device.
    function register(bytes32 pubkey) external {
        if (signers[msg.sender].registered) revert AlreadyRegistered();
        signers[msg.sender] = Signer({pubkey: pubkey, lastCounter: 0, registered: true});
        emit Registered(msg.sender, pubkey);
    }

    /// @notice The digest a device must sign for `claimant` to redeem here.
    /// @dev Commits to chain, contract and claimant, so the same record cannot
    /// be replayed on another chain, another deployment, or by another account.
    function actionDigest(address claimant, bytes32 purpose) public view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(this), claimant, purpose));
    }

    /// @notice Verify a record and admit the caller.
    function redeem(bytes calldata record, bytes32 purpose) external {
        Signer storage sg = signers[msg.sender];
        if (!sg.registered) revert NotRegistered();

        (bool ok, A.Record memory r) =
            A.check(record, sg.pubkey, actionDigest(msg.sender, purpose));
        if (!ok) {
            // Separate the two so a caller can tell a forged signature from a
            // record that is genuine but bound to something else.
            if (A.parse(record).sighash != actionDigest(msg.sender, purpose)) revert WrongDigest();
            revert BadSignature();
        }
        if (r.tier < requiredTier) revert TierTooLow();
        if (r.counter <= sg.lastCounter) revert CounterNotFresh();
        if (!allowedFirmware[r.fwHash]) revert FirmwareNotAllowed();
        if (!allowedCalibration[r.calHash]) revert CalibrationNotAllowed();

        sg.lastCounter = r.counter;
        allowlisted[msg.sender] = true;
        emit Admitted(msg.sender, r.tier, r.counter);
    }
}
