import 'dart:typed_data';

import 'package:chameleonultragui/helpers/mifare_classic/key_check_batched.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('mfClassicKeySlot / slotToRecoveryIndex', () {
    test('Key A slots are even, Key B slots are odd', () {
      expect(mfClassicKeySlot(0, 0), 0); // sector 0 Key A
      expect(mfClassicKeySlot(0, 1), 1); // sector 0 Key B
      expect(mfClassicKeySlot(1, 0), 2); // sector 1 Key A
      expect(mfClassicKeySlot(1, 1), 3);
      expect(mfClassicKeySlot(39, 1), 79); // last slot
    });

    test('slotToRecoveryIndex matches checkMarks layout (sector + 40*keyType)',
        () {
      // checkMarks[slot] layout used by MifareClassicRecovery:
      // Key A of sector N -> index N, Key B -> N + 40
      expect(slotToRecoveryIndex(mfClassicKeySlot(0, 0)), 0);
      expect(slotToRecoveryIndex(mfClassicKeySlot(0, 1)), 40);
      expect(slotToRecoveryIndex(mfClassicKeySlot(5, 1)), 45);
      expect(slotToRecoveryIndex(mfClassicKeySlot(39, 0)), 39);
      expect(slotToRecoveryIndex(mfClassicKeySlot(39, 1)), 79);
    });
  });

  group('buildCheckKeysOfSectorsMask', () {
    test('all-clear mask (check every slot) is 10 zero bytes', () {
      final checked = List.generate(80, (i) => i);
      final mask = buildCheckKeysOfSectorsMask(checked);
      expect(mask.length, 10);
      expect(mask, everyElement(0));
    });

    test('skip-only mask (check nothing) is 10 0xFF bytes', () {
      final mask = buildCheckKeysOfSectorsMask(const []);
      expect(mask, everyElement(0xFF));
    });

    test('checking 16 sectors clears only the first 32 bits (1k card)', () {
      // Firmware iterates sectors 0..39; on a 1k (16-sector) card the upper
      // sectors have no trailer blocks, so their slots must be masked out.
      final checked = <int>[];
      for (var s = 0; s < 16; s++) {
        checked.add(mfClassicKeySlot(s, 0));
        checked.add(mfClassicKeySlot(s, 1));
      }
      final mask = buildCheckKeysOfSectorsMask(checked);
      // 16 sectors * 2 keys = bits 0..31 checked (clear), rest skipped.
      expect(mask.sublist(0, 4), everyElement(0x00));
      expect(mask.sublist(4, 10), everyElement(0xFF));
    });

    test('bit for a single slot maps to the expected byte position', () {
      // Checking ONLY slot 0 (sector 0 key A) clears the MSB of byte 0 and
      // sets every other bit (they are skipped).
      var mask = buildCheckKeysOfSectorsMask([0]);
      expect(mask[0] & 0x80, 0x00); // checked: bit clear
      expect(mask[0] & 0x7F, 0x7F); // everything else skipped
      expect(mask[9], 0xFF);
      // Checking ONLY slot 79 (sector 39 key B) clears the LSB of byte 9.
      mask = buildCheckKeysOfSectorsMask([79]);
      expect(mask[9] & 0x01, 0x00); // checked: bit clear
      expect(mask[9] & 0xFE, 0xFE); // everything else skipped
      expect(mask[0], 0xFF);
    });
  });

  group('parseCheckKeysOfSectorsResponse', () {
    Uint8List makeResponse(Map<int, List<int>> foundKeys) {
      // 10-byte found mask + 480 bytes of keys (6 per slot).
      final data = Uint8List(10 + 80 * 6);
      foundKeys.forEach((slot, key) {
        data[slot >> 3] |= (0x80 >> (slot & 7));
        for (var i = 0; i < 6; i++) {
          data[10 + slot * 6 + i] = key[i];
        }
      });
      return data;
    }

    test('parses found keys back to their slots', () {
      final resp = makeResponse({
        0: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        5: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
      });
      final parsed = parseCheckKeysOfSectorsResponse(resp);
      expect(parsed.length, 2);
      expect(parsed[0], [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
      expect(parsed[5], [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    });

    test('empty response (nothing found) returns empty map', () {
      expect(parseCheckKeysOfSectorsResponse(Uint8List(490)), isEmpty);
    });

    test('truncated response returns empty map', () {
      expect(parseCheckKeysOfSectorsResponse(Uint8List(100)), isEmpty);
    });

    test('round-trips through build mask', () {
      final checked = <int>[];
      for (var s = 0; s < 40; s++) {
        checked.add(mfClassicKeySlot(s, 0));
        checked.add(mfClassicKeySlot(s, 1));
      }
      final mask = buildCheckKeysOfSectorsMask(checked);
      expect(mask, everyElement(0x00));

      final resp = makeResponse({2: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]});
      final parsed = parseCheckKeysOfSectorsResponse(resp);
      expect(parsed.containsKey(2), isTrue);
    });
  });
}
