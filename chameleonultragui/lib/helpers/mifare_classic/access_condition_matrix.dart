// MIFARE Classic Sector Trailer Access Condition Matrix Parser and Generator

class BlockAccessPermission {
  final int blockIndex;
  final int c1;
  final int c2;
  final int c3;
  final String read;
  final String write;
  final String increment;
  final String decrement;
  final String? keyARead;
  final String? keyAWrite;
  final String? accessBitsRead;
  final String? accessBitsWrite;
  final String? keyBRead;
  final String? keyBWrite;
  final bool isTrailer;
  final bool isCorrupted;

  BlockAccessPermission({
    required this.blockIndex,
    required this.c1,
    required this.c2,
    required this.c3,
    required this.read,
    required this.write,
    required this.increment,
    required this.decrement,
    this.keyARead,
    this.keyAWrite,
    this.accessBitsRead,
    this.accessBitsWrite,
    this.keyBRead,
    this.keyBWrite,
    this.isTrailer = false,
    this.isCorrupted = false,
  });

  String get bitTuple => '($c1, $c2, $c3)';
}

class AccessConditionResult {
  final String hexBytes;
  final int byte6;
  final int byte7;
  final int byte8;
  final int byte9;
  final bool isValid;
  final List<String> errors;
  final List<String> warnings;
  final List<BlockAccessPermission> blocks;

  AccessConditionResult({
    required this.hexBytes,
    required this.byte6,
    required this.byte7,
    required this.byte8,
    required this.byte9,
    required this.isValid,
    required this.errors,
    required this.warnings,
    required this.blocks,
  });
}

class AccessConditionMatrixHelper {
  /// Decodes 3-byte or 4-byte access condition hex string (e.g., "FF0780" or "FF078069").
  static AccessConditionResult decodeHex(String hexInput) {
    String clean = hexInput.replaceAll(RegExp(r'[\s:,\-]'), '');
    if (clean.startsWith('0x') || clean.startsWith('0X')) {
      clean = clean.substring(2);
    }

    if (clean.length < 6) {
      return AccessConditionResult(
        hexBytes: clean,
        byte6: 0,
        byte7: 0,
        byte8: 0,
        byte9: 0x69,
        isValid: false,
        errors: ['Hex string must be at least 3 bytes (6 hex chars)'],
        warnings: [],
        blocks: [],
      );
    }

    int b6 = int.parse(clean.substring(0, 2), radix: 16);
    int b7 = int.parse(clean.substring(2, 4), radix: 16);
    int b8 = int.parse(clean.substring(4, 6), radix: 16);
    int b9 = clean.length >= 8 ? int.parse(clean.substring(6, 8), radix: 16) : 0x69;

    List<String> errors = [];
    List<String> warnings = [];
    List<BlockAccessPermission> blocks = [];

    // Verify inverted bit pairs:
    // Byte 6: ~C2_3 ~C2_2 ~C2_1 ~C2_0   ~C1_3 ~C1_2 ~C1_1 ~C1_0
    // Byte 7:  C1_3  C1_2  C1_1  C1_0   ~C3_3 ~C3_2 ~C3_1 ~C3_0
    // Byte 8:  C3_3  C3_2  C3_1  C3_0    C2_3  C2_2  C2_1  C2_0

    for (int i = 0; i < 4; i++) {
      int invC1 = (b6 >> i) & 1;
      int c1 = (b7 >> (4 + i)) & 1;
      bool c1Valid = (invC1 ^ c1) == 1;

      int invC2 = (b6 >> (4 + i)) & 1;
      int c2 = (b8 >> i) & 1;
      bool c2Valid = (invC2 ^ c2) == 1;

      int invC3 = (b7 >> i) & 1;
      int c3 = (b8 >> (4 + i)) & 1;
      bool c3Valid = (invC3 ^ c3) == 1;

      bool corrupted = !c1Valid || !c2Valid || !c3Valid;
      if (corrupted) {
        errors.add(
            'Block $i access bits corrupted: C1=${c1Valid ? "OK" : "INV_ERR"}, C2=${c2Valid ? "OK" : "INV_ERR"}, C3=${c3Valid ? "OK" : "INV_ERR"}');
      }

      if (i < 3) {
        // Data block
        var dataPerm = _resolveDataBlockPermission(i, c1, c2, c3, corrupted);
        blocks.add(dataPerm);
      } else {
        // Trailer block (Block 3)
        var trailerPerm = _resolveTrailerPermission(c1, c2, c3, corrupted);
        blocks.add(trailerPerm);

        if (trailerPerm.keyBRead != 'Never') {
          warnings.add(
              'Key B is readable (${trailerPerm.keyBRead}). Key B cannot be used for sector authentication in this mode.');
        }
        if (trailerPerm.accessBitsWrite == 'Never') {
          warnings.add('Access bits are write-locked (Cannot be changed again).');
        }
      }
    }

    return AccessConditionResult(
      hexBytes: '${b6.toRadixString(16).padLeft(2, '0')}${b7.toRadixString(16).padLeft(2, '0')}${b8.toRadixString(16).padLeft(2, '0')}${b9.toRadixString(16).padLeft(2, '0')}'
          .toUpperCase(),
      byte6: b6,
      byte7: b7,
      byte8: b8,
      byte9: b9,
      isValid: errors.isEmpty,
      errors: errors,
      warnings: warnings,
      blocks: blocks,
    );
  }

  static BlockAccessPermission _resolveDataBlockPermission(
      int index, int c1, int c2, int c3, bool corrupted) {
    if (corrupted) {
      return BlockAccessPermission(
        blockIndex: index,
        c1: c1,
        c2: c2,
        c3: c3,
        read: 'UNKNOWN (CORRUPT)',
        write: 'UNKNOWN (CORRUPT)',
        increment: 'UNKNOWN (CORRUPT)',
        decrement: 'UNKNOWN (CORRUPT)',
        isCorrupted: true,
      );
    }

    int code = (c1 << 2) | (c2 << 1) | c3;
    switch (code) {
      case 0: // 000: Transport configuration
        return BlockAccessPermission(
          blockIndex: index,
          c1: 0,
          c2: 0,
          c3: 0,
          read: 'Key A | B',
          write: 'Key A | B',
          increment: 'Key A | B',
          decrement: 'Key A | B',
        );
      case 2: // 010: Read-only
        return BlockAccessPermission(
          blockIndex: index,
          c1: 0,
          c2: 1,
          c3: 0,
          read: 'Key A | B',
          write: 'Never',
          increment: 'Never',
          decrement: 'Never',
        );
      case 4: // 100
        return BlockAccessPermission(
          blockIndex: index,
          c1: 1,
          c2: 0,
          c3: 0,
          read: 'Key A | B',
          write: 'Key B',
          increment: 'Never',
          decrement: 'Never',
        );
      case 6: // 110: Value block
        return BlockAccessPermission(
          blockIndex: index,
          c1: 1,
          c2: 1,
          c3: 0,
          read: 'Key A | B',
          write: 'Key B',
          increment: 'Key B',
          decrement: 'Key A | B',
        );
      case 1: // 001
        return BlockAccessPermission(
          blockIndex: index,
          c1: 0,
          c2: 0,
          c3: 1,
          read: 'Key A | B',
          write: 'Never',
          increment: 'Never',
          decrement: 'Key A | B',
        );
      case 3: // 011
        return BlockAccessPermission(
          blockIndex: index,
          c1: 0,
          c2: 1,
          c3: 1,
          read: 'Key B',
          write: 'Key B',
          increment: 'Never',
          decrement: 'Never',
        );
      case 5: // 101
        return BlockAccessPermission(
          blockIndex: index,
          c1: 1,
          c2: 0,
          c3: 1,
          read: 'Key B',
          write: 'Never',
          increment: 'Never',
          decrement: 'Never',
        );
      case 7: // 111: Read/Write Never
      default:
        return BlockAccessPermission(
          blockIndex: index,
          c1: 1,
          c2: 1,
          c3: 1,
          read: 'Never',
          write: 'Never',
          increment: 'Never',
          decrement: 'Never',
        );
    }
  }

  static BlockAccessPermission _resolveTrailerPermission(
      int c1, int c2, int c3, bool corrupted) {
    if (corrupted) {
      return BlockAccessPermission(
        blockIndex: 3,
        c1: c1,
        c2: c2,
        c3: c3,
        read: 'CORRUPTED',
        write: 'CORRUPTED',
        increment: 'CORRUPTED',
        decrement: 'CORRUPTED',
        isTrailer: true,
        isCorrupted: true,
      );
    }

    int code = (c1 << 2) | (c2 << 1) | c3;
    switch (code) {
      case 0: // 000
        return BlockAccessPermission(
          blockIndex: 3,
          c1: 0,
          c2: 0,
          c3: 0,
          read: 'N/A',
          write: 'N/A',
          increment: 'N/A',
          decrement: 'N/A',
          isTrailer: true,
          keyARead: 'Never',
          keyAWrite: 'Key A',
          accessBitsRead: 'Key A',
          accessBitsWrite: 'Never',
          keyBRead: 'Key A',
          keyBWrite: 'Key A',
        );
      case 2: // 010
        return BlockAccessPermission(
          blockIndex: 3,
          c1: 0,
          c2: 1,
          c3: 0,
          read: 'N/A',
          write: 'N/A',
          increment: 'N/A',
          decrement: 'N/A',
          isTrailer: true,
          keyARead: 'Never',
          keyAWrite: 'Never',
          accessBitsRead: 'Key A',
          accessBitsWrite: 'Never',
          keyBRead: 'Key A',
          keyBWrite: 'Never',
        );
      case 4: // 100
        return BlockAccessPermission(
          blockIndex: 3,
          c1: 1,
          c2: 0,
          c3: 0,
          read: 'N/A',
          write: 'N/A',
          increment: 'N/A',
          decrement: 'N/A',
          isTrailer: true,
          keyARead: 'Never',
          keyAWrite: 'Key B',
          accessBitsRead: 'Key A | B',
          accessBitsWrite: 'Never',
          keyBRead: 'Never',
          keyBWrite: 'Key B',
        );
      case 6: // 110
        return BlockAccessPermission(
          blockIndex: 3,
          c1: 1,
          c2: 1,
          c3: 0,
          read: 'N/A',
          write: 'N/A',
          increment: 'N/A',
          decrement: 'N/A',
          isTrailer: true,
          keyARead: 'Never',
          keyAWrite: 'Never',
          accessBitsRead: 'Key A | B',
          accessBitsWrite: 'Never',
          keyBRead: 'Never',
          keyBWrite: 'Never',
        );
      case 1: // 001: Standard Transport FF0780
        return BlockAccessPermission(
          blockIndex: 3,
          c1: 0,
          c2: 0,
          c3: 1,
          read: 'N/A',
          write: 'N/A',
          increment: 'N/A',
          decrement: 'N/A',
          isTrailer: true,
          keyARead: 'Never',
          keyAWrite: 'Key A',
          accessBitsRead: 'Key A',
          accessBitsWrite: 'Key A',
          keyBRead: 'Key A',
          keyBWrite: 'Key A',
        );
      case 3: // 011: Standard Secure 7F0788
        return BlockAccessPermission(
          blockIndex: 3,
          c1: 0,
          c2: 1,
          c3: 1,
          read: 'N/A',
          write: 'N/A',
          increment: 'N/A',
          decrement: 'N/A',
          isTrailer: true,
          keyARead: 'Never',
          keyAWrite: 'Key B',
          accessBitsRead: 'Key A | B',
          accessBitsWrite: 'Key B',
          keyBRead: 'Never',
          keyBWrite: 'Key B',
        );
      case 5: // 101
        return BlockAccessPermission(
          blockIndex: 3,
          c1: 1,
          c2: 0,
          c3: 1,
          read: 'N/A',
          write: 'N/A',
          increment: 'N/A',
          decrement: 'N/A',
          isTrailer: true,
          keyARead: 'Never',
          keyAWrite: 'Never',
          accessBitsRead: 'Key A | B',
          accessBitsWrite: 'Key B',
          keyBRead: 'Never',
          keyBWrite: 'Never',
        );
      case 7: // 111
      default:
        return BlockAccessPermission(
          blockIndex: 3,
          c1: 1,
          c2: 1,
          c3: 1,
          read: 'N/A',
          write: 'N/A',
          increment: 'N/A',
          decrement: 'N/A',
          isTrailer: true,
          keyARead: 'Never',
          keyAWrite: 'Never',
          accessBitsRead: 'Key A | B',
          accessBitsWrite: 'Never',
          keyBRead: 'Never',
          keyBWrite: 'Never',
        );
    }
  }

  /// Encodes 4 block configurations (C1, C2, C3 tuples) into 3-byte or 4-byte hex string.
  /// Each entry in [blockTuples] is a 3-element list [c1, c2, c3] (values 0 or 1).
  static String encodeHex(List<List<int>> blockTuples, {int gpb = 0x69}) {
    if (blockTuples.length != 4) {
      throw ArgumentError('Exactly 4 block tuples are required.');
    }

    int b6 = 0;
    int b7 = 0;
    int b8 = 0;

    for (int i = 0; i < 4; i++) {
      int c1 = blockTuples[i][0] & 1;
      int c2 = blockTuples[i][1] & 1;
      int c3 = blockTuples[i][2] & 1;

      int invC1 = c1 ^ 1;
      int invC2 = c2 ^ 1;
      int invC3 = c3 ^ 1;

      // Byte 6: ~C2_3..0 in bits 7..4, ~C1_3..0 in bits 3..0
      b6 |= (invC2 << (4 + i));
      b6 |= (invC1 << i);

      // Byte 7: C1_3..0 in bits 7..4, ~C3_3..0 in bits 3..0
      b7 |= (c1 << (4 + i));
      b7 |= (invC3 << i);

      // Byte 8: C3_3..0 in bits 7..4, C2_3..0 in bits 3..0
      b8 |= (c3 << (4 + i));
      b8 |= (c2 << i);
    }

    String hex6 = b6.toRadixString(16).padLeft(2, '0');
    String hex7 = b7.toRadixString(16).padLeft(2, '0');
    String hex8 = b8.toRadixString(16).padLeft(2, '0');
    String hex9 = gpb.toRadixString(16).padLeft(2, '0');

    return '$hex6$hex7$hex8$hex9'.toUpperCase();
  }
}
