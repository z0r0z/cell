"""Runtime contract for the unreleased CELL PIN-v2 provisioning policy.

Slot 7 holds a random HMAC key. Each candidate PIN requires a metered use
of that key; slots 2/4 hold the resulting high-entropy verifiers. NoMac on
both PIN slots prevents generating a response to replay into CheckMac. ReadKey=1
disables CheckMac Copy for every slot. No slot permits DeriveKey or KDF
writes (KeyConfig.PubInfo is clear), so the metered key cannot be copied
to an unmetered destination. tools/atecc_config.py checks its encoder
against this contract as well as Microchip's field definitions.
"""

SLOT_PIN_STRETCH = 7

# SlotConfig, KeyConfig; the runtime checks the complete tables, not just
# lock flags. Unused slots are closed too: they are potential destinations.
EXPECTED_SLOTS = (
    (0x00A1, 0x02BC),  # wrapping key: metered, authorized by normal PIN
    (0x8081, 0x003C),  # attestation
    (0x8091, 0x003C),  # normal PIN verifier: NoMac, CheckMac only
    (0x4201, 0x003C),  # normal baseline: encrypted write under slot 2
    (0x8091, 0x003C),  # duress PIN verifier: NoMac, CheckMac only
    (0x00A1, 0x04BC),  # wrapping key: metered, authorized by duress PIN
    (0x4401, 0x003C),  # duress baseline: encrypted write under slot 4
    (0x80A1, 0x003C),  # random PIN derivation key: metered, never writable
) + ((0x8081, 0x003C),) * 8


def matches_pin_policy(config: bytes) -> bool:
    if len(config) != 128:
        return False
    return all(
        int.from_bytes(config[20 + 2*i:22 + 2*i], "little") == slot
        and int.from_bytes(config[96 + 2*i:98 + 2*i], "little") == key
        for i, (slot, key) in enumerate(EXPECTED_SLOTS))
