#!/usr/bin/env python3
"""EIP-712 typed data and EIP-7702 delegation, against published values.

Three kinds of check, in the order they are worth anything.

PUBLISHED VECTORS. The EIP-712 worked example ("Ether Mail") carries a domain
separator and a final signing digest in the EIP's own asset file. Both are run
through the same functions the device uses, so a domain built here is checked
against a number nobody in this repository chose.

BINDING. A typed-data signature is worth what its domain pins. Every field of
the domain and of the message is perturbed one at a time, and each must move
the digest. A field that can change without moving the digest is a field the
signature does not commit to, which is how one authorisation becomes valid
against a second deployment.

REFUSALS. Calldata, a self-call, an unregistered account, a delegation on chain
0, an address that fails its EIP-55 checksum, an integer that does not fit the
width the contract declares. Each has to raise rather than be masked.

Where `eth_account` is installed it is used as a second opinion on both digests
-- code from somebody else, satisfied rather than merely agreed with. It is not
a dependency; the suite says so and moves on when it is absent.
"""

from __future__ import annotations

import sys

import eip712
import eth
import ops
import policy
from eip712 import BadTypedData, SmartAccount

# EIP-712, assets/eip-712/Example.js. The domain of the worked example, and the
# two hashes it publishes for it.
MAIL_DOMAIN = ("Ether Mail", "1", 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
MAIL_SEPARATOR = bytes.fromhex(
    "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f")
MAIL_STRUCT_HASH = bytes.fromhex(
    "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e")
MAIL_DIGEST = bytes.fromhex(
    "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2")

ACCOUNT = "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
IMPL = "0xD54cb65224410F3Ff97a8E72f363f224419f4FB0"
BOB = "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
COW = "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"


def _report(checks) -> bool:
    ok = True
    for label, good in checks:
        ok &= bool(good)
        print(f"  {label:<52}{'PASS' if good else 'FAIL'}")
    return ok


def _raises(fn, *a, **kw) -> bool:
    try:
        fn(*a, **kw)
    except BadTypedData:
        return True
    except Exception:                                       # noqa: BLE001
        return False
    return False


def published_vectors() -> bool:
    sep = eip712.domain_separator(*MAIL_DOMAIN)
    return _report([
        ("EIP712Domain typehash", eip712.DOMAIN_TYPEHASH == bytes.fromhex(
            "8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f")),
        ("Ether Mail domain separator", sep == MAIL_SEPARATOR),
        ("Ether Mail signing digest",
         eip712.digest(sep, MAIL_STRUCT_HASH) == MAIL_DIGEST),
        ("Execute typehash is the contract's string",
         eip712.EXECUTE_TYPEHASH == eip712.keccak256(
             b"Execute(address target,uint256 value,bytes data,uint32 nonce)")),
    ])


def account() -> SmartAccount:
    return SmartAccount(label="treasury", address=ACCOUNT, chain_id=1,
                        implementation=IMPL, implementation_label="Multisig v1",
                        threshold=2, owners=(COW, BOB, IMPL))


def struct_layout() -> bool:
    """The Execute hash, against the ABI encoding written out by hand here."""
    target, value, nonce = BOB, 1_500_000_000_000_000_000, 7
    by_hand = eip712.keccak256(
        eip712.EXECUTE_TYPEHASH
        + bytes(12) + bytes.fromhex(target[2:])
        + value.to_bytes(32, "big")
        + eip712.keccak256(b"")
        + nonce.to_bytes(32, "big"))
    return _report([
        ("Execute hashStruct is typehash||target||value||keccak(data)||nonce",
         eip712.execute_struct_hash(target, value, b"", nonce) == by_hand),
        ("empty calldata hashes as keccak(b'')",
         eip712.keccak256(b"").hex().startswith("c5d2460186f7")),
    ])


def binding() -> bool:
    """Every field must move the digest. One that does not is not committed to."""
    a = account()
    base = a.spend_digest(BOB, 10**18, 7)
    from dataclasses import replace
    moves = [
        ("chain id", replace(a, chain_id=11155111).spend_digest(BOB, 10**18, 7)),
        ("account address", replace(a, address=IMPL).spend_digest(BOB, 10**18, 7)),
        ("domain name", replace(a, domain_name="Other").spend_digest(BOB, 10**18, 7)),
        ("domain version", replace(a, domain_version="2").spend_digest(BOB, 10**18, 7)),
        ("destination", a.spend_digest(COW, 10**18, 7)),
        ("amount", a.spend_digest(BOB, 10**18 + 1, 7)),
        ("account nonce", a.spend_digest(BOB, 10**18, 8)),
    ]
    checks = [(f"{name} changes the digest", d != base) for name, d in moves]
    checks.append(("all seven digests are distinct",
                   len({base, *(d for _, d in moves)}) == 8))
    checks.append(("same inputs, same digest", a.spend_digest(BOB, 10**18, 7) == base))
    return _report(checks)


def refusals() -> bool:
    a = account()
    return _report([
        ("calldata is refused",
         _raises(eip712.execute_struct_hash, BOB, 1, b"\xa9\x05\x9c\xbb", 0)),
        ("a self-call is refused", _raises(a.spend_digest, ACCOUNT, 1, 0)),
        ("a nonce past uint32 is refused",
         _raises(eip712.execute_struct_hash, BOB, 1, b"", 2**32)),
        ("a value past uint256 is refused",
         _raises(eip712.execute_struct_hash, BOB, 2**256, b"", 0)),
        ("a bad EIP-55 checksum is refused",
         _raises(eip712.execute_struct_hash,
                 "0xcD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826", 1, b"", 0)),
        ("a short address is refused",
         _raises(eip712.execute_struct_hash, "0xdeadbeef", 1, b"", 0)),
        ("an address that is not a string is refused",
         _raises(eip712.execute_struct_hash, 12345, 1, b"", 0)),
        ("a domain with no name is refused",
         _raises(eip712.domain_separator, "", "1", 1, ACCOUNT)),
        ("a digest from the wrong-sized parts is refused",
         _raises(eip712.digest, b"\x00" * 31, b"\x00" * 32)),
    ])


def registration() -> bool:
    eip712.ACCOUNTS.clear()
    a = account()
    eip712.register_account(a)
    eip712.register_account(a)              # identical repeat is a no-op
    from dataclasses import replace
    checks = [
        ("an account registers", eip712.account("treasury") == a),
        ("registering it again is a no-op", len(eip712.ACCOUNTS) == 1),
        ("a second account under one label is refused",
         _raises(eip712.register_account, replace(a, address=COW))),
        ("one address under a second label is refused",
         _raises(eip712.register_account, replace(a, label="other"))),
        ("an unregistered label is refused", _raises(eip712.account, "nope")),
        ("an unregistered chain is refused",
         _raises(eip712.register_account, replace(a, label="x", chain_id=999999))),
        ("chain 0 is refused",
         _raises(eip712.register_account, replace(a, label="x", chain_id=0))),
        ("the zero address is refused",
         _raises(eip712.register_account,
                 replace(a, label="x", address=eip712.ZERO_ADDRESS))),
        ("an account that is its own implementation is refused",
         _raises(eip712.register_account,
                 replace(a, label="x", implementation=ACCOUNT))),
        ("a threshold past the owner count is refused",
         _raises(eip712.register_account, replace(a, label="x", threshold=9))),
        ("a repeated owner is refused",
         _raises(eip712.register_account,
                 replace(a, label="x", owners=(COW, COW)))),
        ("a label with a control character is refused",
         _raises(eip712.register_account, replace(a, label="tre\nas"))),
    ]
    eip712.ACCOUNTS.clear()
    return _report(checks)


def delegation() -> bool:
    """EIP-7702: keccak(0x05 || rlp([chain_id, address, nonce]))."""
    d = eip712.delegation_digest(1, IMPL, 3)
    by_hand = eip712.keccak256(
        bytes([0x05]) + eth.rlp_encode([1, bytes.fromhex(IMPL[2:]), 3]))
    return _report([
        ("magic byte is 0x05", eip712.MAGIC_7702 == 0x05),
        ("digest is keccak(0x05 || rlp(...))", d == by_hand),
        ("chain id moves it", eip712.delegation_digest(11155111, IMPL, 3) != d),
        ("address moves it", eip712.delegation_digest(1, COW, 3) != d),
        ("nonce moves it", eip712.delegation_digest(1, IMPL, 4) != d),
        ("chain id 0 is refused", _raises(eip712.delegation_digest, 0, IMPL, 3)),
        ("a negative chain id is refused",
         _raises(eip712.delegation_digest, -1, IMPL, 3)),
        ("a nonce past uint256 is refused",
         _raises(eip712.delegation_digest, 1, IMPL, 2**256)),
        ("a bad checksum is refused",
         _raises(eip712.delegation_digest, 1, IMPL.lower()[:-1] + "A", 3)),
    ])


def the_screens() -> bool:
    """Both operations have to fit the panel, with the tier footer reserved."""
    e = ops.SmartAccountExecute(
        amount_wei=1_500_000_000_000_000_000, destination=COW,
        account_label="treasury", account_address=ACCOUNT, chain_id=1,
        chain_name="Ethereum", nonce=7)
    d = ops.Delegation(account_address=COW, implementation=IMPL,
                       implementation_label="Multisig v1", chain_id=1,
                       chain_name="Ethereum", nonce=3)
    rows = ops.DISPLAY_ROWS - ops.CONFIRM_FOOTER_ROWS
    spend = ops.render_for_display(e, reserve=ops.CONFIRM_FOOTER_ROWS)
    deleg = ops.render_for_display(d, reserve=ops.CONFIRM_FOOTER_ROWS)

    def shows(lines, needle):
        return any(needle in ln for ln in lines)

    def unrenderable(**kw):
        try:
            ops.render_for_display(ops.SmartAccountExecute(**{
                "amount_wei": 1, "destination": COW, "account_label": "t",
                "account_address": ACCOUNT, "chain_id": 1,
                "chain_name": "Ethereum", "nonce": 0, **kw}))
        except ops.UnrenderableOperation:
            return True
        return False

    return _report([
        ("the spend screen fits", len(spend) <= rows),
        ("the delegation screen fits", len(deleg) <= rows),
        ("the destination is shown in full", shows(spend, COW[-8:])),
        ("the account is shown in full", shows(spend, ACCOUNT[-8:])),
        ("the account nonce is shown", shows(spend, "nonce    7")),
        ("the chain is named, not numbered alone", shows(spend, "Ethereum (1)")),
        ("the relayer's fee is stated", shows(spend, "relays it")),
        ("the code being delegated to is shown in full", shows(deleg, IMPL[-8:])),
        ("the delegation says it persists", shows(deleg, "until delegated again")),
        ("an unnamed chain is unrenderable", unrenderable(chain_name="")),
        ("an unlabelled account is unrenderable", unrenderable(account_label="")),
        ("a self-call is unrenderable", unrenderable(destination=ACCOUNT)),
        ("no ticker is unrenderable", unrenderable(ticker="")),
        ("chain 0 is unrenderable as a delegation",
         _raises_unrenderable(ops.Delegation, account_address=COW,
                              implementation=IMPL, implementation_label="m",
                              chain_id=0, chain_name="x", nonce=0)),
        ("an unregistered implementation is unrenderable",
         _raises_unrenderable(ops.Delegation, account_address=COW,
                              implementation=IMPL, implementation_label="",
                              chain_id=1, chain_name="Ethereum", nonce=0)),
    ])


def _raises_unrenderable(cls, **kw) -> bool:
    try:
        ops.render_for_display(cls(**kw))
    except ops.UnrenderableOperation:
        return True
    except Exception:                                       # noqa: BLE001
        return False
    return False


def the_policy() -> bool:
    p = policy.Policy()
    return _report([
        ("a delegation needs blood, with no floor set",
         p.required_tier("account.delegate") == policy.Tier.BLOOD),
        ("a delegation needs blood at amount 0",
         p.required_tier("account.delegate", 0) == policy.Tier.BLOOD),
        ("it is in ALWAYS_BLOOD, so no policy can unlock it",
         "account.delegate" in policy.ALWAYS_BLOOD),
        ("a smart-account spend is priced as a spend",
         p.required_tier("tx.send", 0) == policy.Tier.TOUCH),
        ("every operation class is priced",
         not ops.op_classes() - policy.KNOWN_OPS),
    ])


def parsing() -> bool:
    good = {"type": "account_execute", "amount_wei": 1, "destination": COW,
            "account_label": "t", "account_address": ACCOUNT, "chain_id": 1,
            "chain_name": "Ethereum", "nonce": 0}

    def refuses(**kw):
        payload = dict(good, **kw)
        try:
            ops.parse(payload)
        except ops.UnrenderableOperation:
            return True
        return False

    return _report([
        ("a well-formed payload parses",
         isinstance(ops.parse(dict(good)), ops.SmartAccountExecute)),
        ("an unknown field is refused", refuses(gas_limit=21000)),
        ("a missing field is refused", _missing_refused(good)),
        ("a field of the wrong type is refused", refuses(amount_wei="1")),
        ("a delegation payload parses",
         isinstance(ops.parse({"type": "account_delegate",
                               "account_address": COW, "implementation": IMPL,
                               "implementation_label": "Multisig v1",
                               "chain_id": 1, "chain_name": "Ethereum",
                               "nonce": 0}), ops.Delegation)),
        ("calldata smuggled as a field is refused",
         refuses(data="0xa9059cbb")),
    ])


def _missing_refused(good) -> bool:
    partial = {k: v for k, v in good.items() if k != "destination"}
    try:
        ops.parse(partial)
    except ops.UnrenderableOperation:
        return True
    return False


def second_opinion() -> bool:
    """eth_account on both digests, and on the signature, when it is installed.

    Not a dependency. A second opinion that shared our code would not be one,
    so this is the same argument test_consensus.py makes for the Bitcoin side:
    hand the output to somebody else's implementation and see whether it is
    satisfied.
    """
    try:
        from eth_account import Account
        from eth_account.messages import encode_typed_data
    except ImportError:
        print("  eth_account not installed -- skipped, and not a dependency")
        return True
    a = account()
    typed = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}],
            "Execute": [
                {"name": "target", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "data", "type": "bytes"},
                {"name": "nonce", "type": "uint32"}]},
        "primaryType": "Execute",
        "domain": {"name": a.domain_name, "version": a.domain_version,
                   "chainId": a.chain_id, "verifyingContract": a.address},
        "message": {"target": BOB, "value": 10**18, "data": b"", "nonce": 7},
    }
    # SignableMessage is (version, header, body): the 0x01 version byte, the
    # domain separator, and the struct hash. Comparing the three separately
    # says WHERE an encoder disagrees, which a single digest comparison never
    # does -- and the first version of this check compared the wrong two of
    # them and reported a disagreement that was not there.
    m = encode_typed_data(full_message=typed)
    theirs = eip712.keccak256(b"\x19" + m.version + m.header + m.body)

    # The delegation, against their own EIP-7702 signer.
    sk = bytes.fromhex("00" * 31 + "07")
    signed = Account.sign_authorization(
        {"chainId": 1, "address": IMPL, "nonce": 3}, sk)
    their_auth = bytes(signed.authorization_hash)

    # And the signature itself, recovered by their code. This is what settles
    # the v byte: 27 + y_parity is the branch an account contract reads as
    # ECDSA, and getting it wrong produces a signature that recovers to
    # somebody who is not an owner.
    import secp256k1 as ec
    from addresses import eth_address
    digest = a.spend_digest(BOB, 10**18, 7)
    r, s_, rec = ec.ecdsa_sign(digest, sk, grind_low_r=False)
    sig = r.to_bytes(32, "big") + s_.to_bytes(32, "big") + bytes([27 + (rec & 1)])
    recovered = Account._recover_hash(digest, signature=sig)

    return _report([
        ("eth_account agrees on the domain separator",
         bytes(m.header) == a.separator()),
        ("eth_account agrees on the Execute struct hash",
         bytes(m.body) == eip712.execute_struct_hash(BOB, 10**18, b"", 7)),
        ("eth_account agrees on the signing digest", theirs == digest),
        ("eth_account agrees on the EIP-7702 authorisation hash",
         their_auth == eip712.delegation_digest(1, IMPL, 3)),
        ("eth_account recovers our signature to our own address",
         recovered.lower() == eth_address(ec.pubkey_compressed(sk)).lower()),
    ])


def _expected_address() -> str:
    """The signing address, derived here from the mnemonic independently.

    Comparing the wallet's answer against the wallet's own answer proves
    nothing, so this walks BIP-39 to BIP-32 to EIP-55 without going through
    the code under test.
    """
    import bip32
    import bip39
    import wallet
    from addresses import eth_address
    root = bip32.ExtendedKey.from_seed(bip39.to_seed(_MNEMONIC()))
    return eth_address(root.derive(wallet.eth_path(0, 0)).pubkey)


def _MNEMONIC() -> str:
    from test_wallet import MNEMONIC
    return MNEMONIC


def end_to_end() -> bool:
    """Both entry points, through the whole unlock chain, on a soft chip.

    The point of running the real chain rather than calling the digest builder
    is the recovery check at the end of it. An EVM account verifies by
    recovering an address from the signature, so a signature that is correct
    apart from its parity byte is not rejected as malformed. It is credited to
    somebody else, and the account refuses an owner it does not have -- after
    the owner has already bled.
    """
    import policy as pol_mod
    import wallet
    from se import SoftSE
    from test_wallet import MNEMONIC, PIN, gate_ok

    se = SoftSE(pin=PIN)
    prov = wallet.provision(MNEMONIC, se, PIN, script_types=("p2wpkh",))
    fw, cal = b"\x11" * 32, b"\x22" * 32
    eip712.ACCOUNTS.clear()
    eip712.register_account(account())
    shown: list[list[str]] = []

    def confirm(lines):
        shown.append(lines)
        return True

    spend = wallet.sign_account_execute(
        "treasury", BOB, 10**18, 7, prov, se, pol_mod.Policy(), fw, cal,
        confirm, gate_ok, PIN)
    deleg = wallet.sign_delegation(
        "treasury", ACCOUNT, 3, prov, se, pol_mod.Policy(), fw, cal,
        confirm, gate_ok, PIN)

    def refused(fn):
        try:
            fn()
        except Exception:                                   # noqa: BLE001
            return True
        return False

    checks = [
        ("a smart-account spend signs", len(spend.signature) == 65),
        ("v is 27 or 28, as the contract's ECDSA branch requires",
         spend.signature[64] in (27, 28)),
        ("the digest returned is the one the account will check",
         spend.digest == "0x" + account().spend_digest(BOB, 10**18, 7).hex()),
        ("it recovers to the address this seed derives",
         spend.signer_address == _expected_address()),
        ("the spend ran at touch tier", spend.tier is pol_mod.Tier.TOUCH),
        ("an attestation rides along", len(spend.attestation) > 0),
        ("the destination was on the screen",
         any(BOB[-8:] in ln for ln in spend.display)),
        ("a delegation signs", len(deleg.signature) == 65),
        ("the delegation ran at BLOOD tier, with no policy set",
         deleg.tier is pol_mod.Tier.BLOOD),
        ("the delegation digest is the EIP-7702 one",
         deleg.digest == "0x" + eip712.delegation_digest(
             1, IMPL, 3).hex()),
        # A 7702 digest commits to the implementation and the nonce and NOT to
        # the address being delegated -- the authority is whoever signs. So an
        # account address taken from the payload would be a screen, not a
        # fact: the owner reads an address they do not recognise, approves it
        # at blood tier, and delegates their own.
        ("a delegation for an address the device was not told about is refused",
         refused(lambda: wallet.sign_delegation(
             "treasury", COW, 3, prov, se, pol_mod.Policy(), fw, cal,
             confirm, gate_ok, PIN))),
        ("the screen names the implementation, not the account",
         any("Multisig v1" in ln for ln in deleg.display)),
        ("an unregistered account cannot be spent from",
         refused(lambda: wallet.sign_account_execute(
             "nope", BOB, 1, 0, prov, se, pol_mod.Policy(), fw, cal,
             confirm, gate_ok, PIN))),
        ("declining at the confirmation signs nothing",
         refused(lambda: wallet.sign_account_execute(
             "treasury", BOB, 1, 0, prov, se, pol_mod.Policy(), fw, cal,
             lambda _l: False, gate_ok, PIN))),
        ("a failed gate signs nothing",
         refused(lambda: wallet.sign_account_execute(
             "treasury", BOB, 1, 0, prov, se, pol_mod.Policy(), fw, cal,
             confirm, lambda _t: (False, {}), PIN))),
        ("a wrong PIN signs nothing",
         refused(lambda: wallet.sign_account_execute(
             "treasury", BOB, 1, 0, prov, se, pol_mod.Policy(), fw, cal,
             confirm, gate_ok, "00000000"))),
    ]
    eip712.ACCOUNTS.clear()
    return _report(checks)


def main() -> int:
    print("EIP-712 typed data, and the EIP-7702 delegation authorisation\n")
    print("Published vectors (EIP-712 assets/Example.js):")
    a = published_vectors()
    print("\nThe Execute struct, against the ABI encoding written out by hand:")
    b = struct_layout()
    print("\nWhat the signature is bound to:")
    c = binding()
    print("\nRefusals:")
    d = refusals()
    print("\nAccount registration:")
    e = registration()
    print("\nEIP-7702 delegation:")
    f = delegation()
    print("\nThe screens, on a 240x240 panel:")
    g = the_screens()
    print("\nTier policy:")
    h = the_policy()
    print("\nParsing a scanned payload:")
    i = parsing()
    print("\nThrough the whole unlock chain, on a soft chip:")
    k = end_to_end()
    print("\nA second opinion:")
    j = second_opinion()
    ok = all([a, b, c, d, e, f, g, h, i, j, k])
    print("\n" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
