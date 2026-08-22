// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

/// @title CellAttestation
/// @notice Verifies a CELL liveness attestation on chain.
///
/// A CELL device signs a claim about which gate it ran for a given action. The
/// claim is separate from the spend signature, under a key generated at
/// provisioning and never exported. Off chain a co-signer checks it with
/// firmware/attest.py. This library is the same check in Solidity, so a
/// contract can gate on "this was authorised with blood".
///
/// WHAT IT PROVES. A device holding the registered key states that it ran the
/// blood gate for this digest. As with any hardware attestation, that rests on
/// the firmware and the tamper seal: extract the key and you can sign claims
/// without bleeding. So treat a passing check as raising the cost of faking a
/// human, not as proof of a unique one, and keep the firmware allowlist tight.
///
/// WHY IT IS WORTH THE GAS. A script can produce a million signatures. A body
/// produces about two blood attestations a day, each costing a lancet and ten
/// minutes. For allowlists, mints and quorum votes that is a rate limit
/// denominated in something an attacker cannot buy more of.
library CellAttestation {
    // secp256k1
    uint256 internal constant P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 internal constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    // sha256("CELL/attest-v1") and sha256("BIP0340/challenge"). BIP-340 tagged
    // hashing is sha256-based, not keccak, so both tags are precomputed here
    // and the sha256 precompile does the rest.
    bytes32 internal constant TAG_ATTEST =
        0xbde58f13c478c59a64b81a00d46799533159d3ceb252a0c610f0788da0e98cb7;
    bytes32 internal constant TAG_CHALLENGE =
        0x7bb52d7a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48d37c;

    uint256 internal constant RECORD_LEN = 174;   // body
    uint256 internal constant PACKED_LEN = 238;   // body + 64-byte signature
    bytes4  internal constant MAGIC = 0x43454c4c; // "CELL"
    uint8   internal constant VERSION = 1;

    uint8 internal constant TIER_TOUCH = 1;
    uint8 internal constant TIER_BLOOD = 2;

    struct Record {
        uint8   tier;
        uint64  counter;
        bytes32 sighash;    // what the claim is bound to
        bytes32 fwHash;     // which firmware made it
        bytes32 calHash;    // which calibration was in force
        bytes32 liveHash;   // the gate measurements it rests on
        bytes32 pubkey;     // x-only attestation key
    }

    error BadLength();
    error BadMagic();
    error BadVersion();
    error BadTier();

    /// @notice Parse a packed record. Reverts rather than returning garbage:
    /// every field here is load-bearing, so a malformed record is not a record.
    function parse(bytes calldata blob) internal pure returns (Record memory r) {
        if (blob.length != PACKED_LEN) revert BadLength();
        if (bytes4(blob[0:4]) != MAGIC) revert BadMagic();
        if (uint8(blob[4]) != VERSION) revert BadVersion();
        r.tier = uint8(blob[5]);
        if (r.tier != TIER_TOUCH && r.tier != TIER_BLOOD) revert BadTier();
        r.counter  = uint64(bytes8(blob[6:14]));
        r.sighash  = bytes32(blob[14:46]);
        r.fwHash   = bytes32(blob[46:78]);
        r.calHash  = bytes32(blob[78:110]);
        r.liveHash = bytes32(blob[110:142]);
        r.pubkey   = bytes32(blob[142:174]);
    }

    /// @notice BIP-340 tagged hash: sha256(sha256(tag) || sha256(tag) || msg).
    function taggedHash(bytes32 tag, bytes memory msg_) internal view returns (bytes32) {
        return sha256(abi.encodePacked(tag, tag, msg_));
    }

    /// @notice The digest the device signed, recomputed from the body.
    function digest(bytes calldata blob) internal view returns (bytes32) {
        return taggedHash(TAG_ATTEST, blob[0:RECORD_LEN]);
    }

    /// @notice Verify a BIP-340 Schnorr signature.
    ///
    /// The EVM has no secp256k1 point arithmetic, so this rearranges the check
    /// into one `ecrecover` call. `ecrecover(h, v, r, s)` returns the address of
    ///
    ///     Q = r^-1 * (s*R - h*G),   R being the point with x-coordinate r
    ///
    /// Verification wants R' = s*G - e*P and R'.x == rx. Putting the public key
    /// in as `r` makes R = P, and then choosing
    ///
    ///     h = -rx_used * s   and   s_field = -rx_used * e     (mod N)
    ///
    /// with rx_used = px gives Q = s*G - e*P, which is R'. Comparing addresses
    /// rather than points is what keeps it to one precompile call.
    ///
    /// The claimed R is then lifted from its x-coordinate so the two addresses
    /// can be compared. That lift is the only other cost: one modexp for the
    /// square root, which also proves rx is on the curve.
    function verifySchnorr(bytes32 px, bytes32 rx, bytes32 s, bytes32 m)
        internal
        view
        returns (bool)
    {
        uint256 pxU = uint256(px);
        uint256 rxU = uint256(rx);
        uint256 sU  = uint256(s);
        // Range checks first. ecrecover silently returns address(0) on bad
        // input, and address(0) must never be mistaken for a valid recovery.
        if (pxU == 0 || pxU >= P) return false;
        if (rxU == 0 || rxU >= P) return false;
        if (sU >= N) return false;

        // e = int(taggedHash("BIP0340/challenge", rx || px || m)) mod n
        uint256 e = uint256(taggedHash(TAG_CHALLENGE, abi.encodePacked(rx, px, m))) % N;
        if (e == 0) return false;

        // px must be a valid x-only key, i.e. on the curve. lift() proves it.
        (bool okP, ) = lift(pxU);
        if (!okP) return false;

        uint256 h = N - mulmod(sU, pxU % N, N);
        uint256 sf = N - mulmod(e, pxU % N, N);
        // v = 27: BIP-340 x-only keys are the even-y lift by definition.
        address recovered = ecrecover(bytes32(h), 27, px, bytes32(sf));
        if (recovered == address(0)) return false;

        (bool okR, uint256 ry) = lift(rxU);
        if (!okR) return false;
        return recovered == address(uint160(uint256(keccak256(abi.encodePacked(rxU, ry)))));
    }

    /// @notice Even-y point with the given x, if one exists.
    /// @dev y = (x^3 + 7)^((P+1)/4) mod P, valid because P = 3 mod 4. The
    /// squaring check is what rejects an x that is not on the curve at all.
    function lift(uint256 x) internal view returns (bool ok, uint256 y) {
        uint256 c = addmod(mulmod(mulmod(x, x, P), x, P), 7, P);
        y = modexp(c, (P + 1) / 4, P);
        if (mulmod(y, y, P) != c) return (false, 0);
        if (y % 2 == 1) y = P - y;
        return (true, y);
    }

    function modexp(uint256 b, uint256 e, uint256 m) internal view returns (uint256 r) {
        assembly {
            let p := mload(0x40)
            mstore(p, 0x20) mstore(add(p, 0x20), 0x20) mstore(add(p, 0x40), 0x20)
            mstore(add(p, 0x60), b) mstore(add(p, 0x80), e) mstore(add(p, 0xa0), m)
            if iszero(staticcall(gas(), 0x05, p, 0xc0, p, 0x20)) { revert(0, 0) }
            r := mload(p)
        }
    }

    /// @notice Full check: parse, verify the signature, and confirm the record
    /// is bound to what the caller expects.
    function check(bytes calldata blob, bytes32 expectPubkey, bytes32 expectSighash)
        internal
        view
        returns (bool ok, Record memory r)
    {
        r = parse(blob);
        if (r.pubkey != expectPubkey) return (false, r);
        if (r.sighash != expectSighash) return (false, r);
        bytes32 rx = bytes32(blob[RECORD_LEN:RECORD_LEN + 32]);
        bytes32 s  = bytes32(blob[RECORD_LEN + 32:PACKED_LEN]);
        ok = verifySchnorr(r.pubkey, rx, s, digest(blob));
    }
}
