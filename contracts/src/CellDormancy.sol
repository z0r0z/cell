// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {CellRegistry} from "./CellRegistry.sol";

/// @title CellDormancy
/// @notice Release something to a beneficiary once the owner has stopped
/// proving they are alive.
///
/// Every dead-man switch in self-custody keys off signing activity, which
/// answers the wrong question. "This key moved" is not "this person is alive":
/// a stolen key resets the clock, and an owner who simply does not spend for a
/// year looks dead. CellRegistry.heartbeat records something different, a
/// device asserting that its touch gate measured a living body, and this reads
/// that number.
///
/// TWO PHASES, DELIBERATELY. A claim does not release anything. It starts a
/// challenge window, and one beacon during that window cancels it. A device
/// that spent six months in a drawer is the ordinary case, not the attack, and
/// it is recoverable with fifteen seconds of a fingertip.
///
/// WHAT THIS CONTRACT DOES NOT DO. It holds no funds and moves nothing. It
/// publishes one boolean and the reasoning behind it, so a vault, a timelock
/// or a multisig can read it without this contract having custody of anything.
/// A dead-man switch that holds the assets is a dead-man switch that can lose
/// them to its own bug.
contract CellDormancy {
    CellRegistry public immutable registry;

    /// @notice The person whose life is being attested to.
    address public immutable owner;
    /// @notice Who may claim after the silence.
    address public immutable beneficiary;
    /// @notice How long the owner must be silent before a claim may start.
    uint64  public immutable dormancyPeriod;
    /// @notice How long a claim is open to being cancelled by one beacon.
    uint64  public immutable challengeWindow;

    /// @notice When the open claim started, or 0 if there is none.
    uint64  public claimStartedAt;
    /// @notice True once the claim has survived its challenge window.
    bool    public released;

    event ClaimStarted(uint64 at, uint64 finalizeAfter);
    event ClaimCancelled(uint64 at, uint64 lastSeen);
    event Released(uint64 at, uint64 lastSeen);

    error NotBeneficiary();
    error NotDormantYet();
    error ClaimAlreadyOpen();
    error NoClaimOpen();
    error AlreadyReleased();
    error StillInChallengeWindow();
    error OwnerIsAlive();
    error OwnerIsNotAlive();
    error BadConfiguration();

    constructor(CellRegistry _registry, address _owner, address _beneficiary,
                uint64 _dormancyPeriod, uint64 _challengeWindow) {
        if (_owner == address(0) || _beneficiary == address(0)
            || _owner == _beneficiary) revert BadConfiguration();
        // TWO beacon periods, not one. `heartbeat` accepts a beacon only while
        // its epoch is the current one, so an owner who beacons in every
        // single period can still legitimately be silent for one second short
        // of 2 * EPOCH_SECONDS -- the first second of epoch N to the last
        // second of epoch N+1. A one-period floor therefore fires on exactly
        // the owner this check exists to protect: alive, compliant, and
        // between beacons.
        if (_dormancyPeriod < 2 * _registry.EPOCH_SECONDS()) revert BadConfiguration();
        if (_challengeWindow == 0) revert BadConfiguration();
        registry = _registry;
        owner = _owner;
        beneficiary = _beneficiary;
        dormancyPeriod = _dormancyPeriod;
        challengeWindow = _challengeWindow;
    }

    /// @notice Seconds since the owner last proved they were alive.
    function silence() public view returns (uint64) {
        return registry.dormantFor(owner);
    }

    /// @notice Open a claim. Releases nothing on its own.
    function startClaim() external {
        if (msg.sender != beneficiary) revert NotBeneficiary();
        if (released) revert AlreadyReleased();
        if (claimStartedAt != 0) revert ClaimAlreadyOpen();
        if (silence() < dormancyPeriod) revert NotDormantYet();
        claimStartedAt = uint64(block.timestamp);
        emit ClaimStarted(claimStartedAt, claimStartedAt + challengeWindow);
    }

    /// @notice Cancel an open claim, on the evidence of one beacon.
    /// @dev Callable by anybody. What matters is the registry's number, not
    /// who noticed it, and an owner who has just proved they are alive should
    /// not also have to be the one who transacts.
    function cancelClaim() external {
        if (claimStartedAt == 0) revert NoClaimOpen();
        if (released) revert AlreadyReleased();
        uint64 seen = registry.lastSeen(owner);
        // Not-later-than, so a beacon in the same block as the claim counts
        // for the owner. Ties go to the living: releasing an inheritance on a
        // tie is the worse of the two errors by a long way.
        if (seen < claimStartedAt) revert OwnerIsNotAlive();
        claimStartedAt = 0;
        emit ClaimCancelled(uint64(block.timestamp), seen);
    }

    /// @notice Close a claim that survived its window.
    function finalize() external {
        if (msg.sender != beneficiary) revert NotBeneficiary();
        if (released) revert AlreadyReleased();
        if (claimStartedAt == 0) revert NoClaimOpen();
        if (block.timestamp < claimStartedAt + challengeWindow) {
            revert StillInChallengeWindow();
        }
        uint64 seen = registry.lastSeen(owner);
        // The window is judged on the beacon, not on the calendar. A beacon
        // that landed during the window and was never used to cancel still
        // means the owner was here.
        if (seen >= claimStartedAt) revert OwnerIsAlive();
        released = true;
        emit Released(uint64(block.timestamp), seen);
    }
}
