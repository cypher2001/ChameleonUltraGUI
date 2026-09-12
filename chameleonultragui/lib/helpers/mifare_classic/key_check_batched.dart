import 'dart:typed_data';

/// Helpers for the batched MIFARE Classic key check (cmd 2012,
/// `mf1CheckKeysOfSectors`).
///
/// Wire format (verified against RRG firmware `mf1_toolbox_check_keys_of_sectors`):
///  - request data:  10-byte mask + N * 6-byte keys
///  - response data: 10-byte found mask + 40 * 2 * 6 = 480 bytes of keys
///
/// Both masks use 80 bits, one bit per (sector, key type) slot:
///  - bit index k   = slot
///  - sector        = k >> 1
///  - key type      = k & 1   (0 = Key A, 1 = Key B)   [even bit = A, odd bit = B]
///  - bit set       = skip (request) / found (response)
///  - bits are big-endian within each byte (bit 0 = MSB of byte 0).
///
/// Note the GUI's internal `checkMarks`/`validKeys` arrays use a different
/// layout (`sector + 40 * keyType`), so slots must be translated when
/// integrating with recovery state.
const int kCheckKeysSectorSlotCount = 80;

/// Returns the slot index for a [sector] and [keyType] (0 = A, 1 = B).
int mfClassicKeySlot(int sector, int keyType) => (sector << 1) | keyType;

/// Decodes a slot index into the recovery-array index
/// (`sector + 40 * keyType`, matching `MifareClassicRecovery.checkMarks`).
int slotToRecoveryIndex(int slot) {
  final sector = slot >> 1;
  final keyType = slot & 1;
  return sector + keyType * 40;
}

/// Builds the 10-byte request mask for cmd 2012.
///
/// Pass the list of slot indices that should be CHECKED; every other bit is
/// set (= skip). Sectors beyond the card's physical sector count must not be
/// checked, otherwise the firmware aborts with tag-lost when authenticating a
/// non-existent trailer block.
Uint8List buildCheckKeysOfSectorsMask(Iterable<int> checkedSlots) {
  final mask = Uint8List(10);
  final check = checkedSlots.toSet();
  for (var slot = 0; slot < kCheckKeysSectorSlotCount; slot++) {
    if (!check.contains(slot)) {
      mask[slot >> 3] |= (0x80 >> (slot & 7));
    }
  }
  return mask;
}

/// Parses a cmd 2012 response into a map of slot index -> found 6-byte key.
///
/// Returns an empty map for truncated responses (tag lost mid-check returns
/// no payload with a non-zero status, which the caller handles separately).
Map<int, Uint8List> parseCheckKeysOfSectorsResponse(Uint8List data) {
  if (data.length < 10 + kCheckKeysSectorSlotCount * 6) {
    return {};
  }
  final found = <int, Uint8List>{};
  for (var slot = 0; slot < kCheckKeysSectorSlotCount; slot++) {
    if ((data[slot >> 3] & (0x80 >> (slot & 7))) != 0) {
      final offset = 10 + slot * 6;
      found[slot] = Uint8List.fromList(data.sublist(offset, offset + 6));
    }
  }
  return found;
}
