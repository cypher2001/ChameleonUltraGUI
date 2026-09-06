// Wiegand format decoder and encoder for access control research

enum WiegandFormat {
  wiegand26('26-bit (H10301)', 26),
  wiegand34('34-bit Standard', 34),
  wiegand37H10304('37-bit (H10304 - with FC)', 37),
  wiegand37H10302('37-bit (H10302 - 35-bit ID)', 37);

  final String label;
  final int bitCount;
  const WiegandFormat(this.label, this.bitCount);
}

class WiegandResult {
  final WiegandFormat format;
  final int facilityCode;
  final int cardNumber;
  final String rawBinary;
  final String rawHex;
  final bool evenParityValid;
  final bool oddParityValid;
  final bool isValid;
  final String? errorMessage;

  WiegandResult({
    required this.format,
    required this.facilityCode,
    required this.cardNumber,
    required this.rawBinary,
    required this.rawHex,
    required this.evenParityValid,
    required this.oddParityValid,
    required this.isValid,
    this.errorMessage,
  });
}

class WiegandHelper {
  /// Counts set bits (1s) in a binary string substring.
  static int countOnes(String binaryStr, int start, int end) {
    int count = 0;
    for (int i = start; i < end; i++) {
      if (i < binaryStr.length && binaryStr[i] == '1') {
        count++;
      }
    }
    return count;
  }

  /// Calculates even parity bit for a binary string range [start, end).
  /// Even parity: total number of 1s (including parity bit) is even.
  static int calcEvenParity(String binaryStr, int start, int end) {
    int ones = countOnes(binaryStr, start, end);
    return (ones % 2 == 0) ? 0 : 1;
  }

  /// Calculates odd parity bit for a binary string range [start, end).
  /// Odd parity: total number of 1s (including parity bit) is odd.
  static int calcOddParity(String binaryStr, int start, int end) {
    int ones = countOnes(binaryStr, start, end);
    return (ones % 2 == 0) ? 1 : 0;
  }

  /// Normalizes input string (hex or binary) to a clean binary string of at least [targetBits].
  static String normalizeToBinary(String input, {int? targetBits}) {
    String trimmed = input.replaceAll(RegExp(r'[\s:,\-]'), '');
    if (trimmed.isEmpty) return '';

    // If input contains only 0 and 1, treat as binary
    if (RegExp(r'^[01]+$').hasMatch(trimmed)) {
      if (targetBits != null && trimmed.length < targetBits) {
        return trimmed.padLeft(targetBits, '0');
      }
      return trimmed;
    }

    // Treat as hex
    String cleanHex = trimmed.startsWith('0x') || trimmed.startsWith('0X')
        ? trimmed.substring(2)
        : trimmed;

    BigInt? value = BigInt.tryParse(cleanHex, radix: 16);
    if (value == null) return '';

    String bin = value.toRadixString(2);
    if (targetBits != null) {
      if (bin.length < targetBits) {
        bin = bin.padLeft(targetBits, '0');
      }
    } else {
      // Pad to nearest multiple of 8 if unspecified
      int remainder = bin.length % 8;
      if (remainder != 0) {
        bin = bin.padLeft(bin.length + (8 - remainder), '0');
      }
    }
    return bin;
  }

  /// Converts binary string to hex string with uppercase padding.
  static String binaryToHex(String binary) {
    if (binary.isEmpty) return '';
    BigInt value = BigInt.parse(binary, radix: 2);
    int hexLength = (binary.length / 4).ceil();
    return value.toRadixString(16).toUpperCase().padLeft(hexLength, '0');
  }

  /// Decode Standard 26-bit Wiegand (H10301)
  /// [0]       Even parity for bits 1..12
  /// [1..8]    Facility Code (8 bits, 0-255)
  /// [9..24]   Card Number (16 bits, 0-65535)
  /// [25]      Odd parity for bits 13..24
  static WiegandResult decode26Bit(String input) {
    String bin = normalizeToBinary(input, targetBits: 26);
    if (bin.length > 26) {
      bin = bin.substring(bin.length - 26);
    }
    if (bin.length < 26) {
      return WiegandResult(
        format: WiegandFormat.wiegand26,
        facilityCode: 0,
        cardNumber: 0,
        rawBinary: bin,
        rawHex: binaryToHex(bin),
        evenParityValid: false,
        oddParityValid: false,
        isValid: false,
        errorMessage: 'Input must contain at least 26 bits',
      );
    }

    int leadingParityBit = int.parse(bin[0]);
    int fcOnes = countOnes(bin, 1, 13);
    bool evenValid = ((leadingParityBit + fcOnes) % 2 == 0);

    int trailingParityBit = int.parse(bin[25]);
    int cnOnes = countOnes(bin, 13, 25);
    bool oddValid = ((trailingParityBit + cnOnes) % 2 == 1);

    int fc = int.parse(bin.substring(1, 9), radix: 2);
    int cn = int.parse(bin.substring(9, 25), radix: 2);

    return WiegandResult(
      format: WiegandFormat.wiegand26,
      facilityCode: fc,
      cardNumber: cn,
      rawBinary: bin,
      rawHex: binaryToHex(bin),
      evenParityValid: evenValid,
      oddParityValid: oddValid,
      isValid: evenValid && oddValid,
    );
  }

  /// Encode Standard 26-bit Wiegand (H10301)
  static WiegandResult encode26Bit(int facilityCode, int cardNumber) {
    int fc = facilityCode.clamp(0, 255);
    int cn = cardNumber.clamp(0, 65535);

    String fcBin = fc.toRadixString(2).padLeft(8, '0');
    String cnBin = cn.toRadixString(2).padLeft(16, '0');
    String data24 = fcBin + cnBin; // 24 bits

    // Leading even parity over data24[0..12] (first 12 bits)
    int pEven = (countOnes(data24, 0, 12) % 2 == 0) ? 0 : 1;
    // Trailing odd parity over data24[12..24] (last 12 bits)
    int pOdd = (countOnes(data24, 12, 24) % 2 == 0) ? 1 : 0;

    String bin = '$pEven$data24$pOdd';

    return WiegandResult(
      format: WiegandFormat.wiegand26,
      facilityCode: fc,
      cardNumber: cn,
      rawBinary: bin,
      rawHex: binaryToHex(bin),
      evenParityValid: true,
      oddParityValid: true,
      isValid: true,
    );
  }

  /// Decode Standard 34-bit Wiegand
  /// [0]       Even parity for bits 1..16
  /// [1..16]   Facility Code (16 bits, 0-65535)
  /// [17..32]  Card Number (16 bits, 0-65535)
  /// [33]      Odd parity for bits 17..32
  static WiegandResult decode34Bit(String input) {
    String bin = normalizeToBinary(input, targetBits: 34);
    if (bin.length > 34) {
      bin = bin.substring(bin.length - 34);
    }
    if (bin.length < 34) {
      return WiegandResult(
        format: WiegandFormat.wiegand34,
        facilityCode: 0,
        cardNumber: 0,
        rawBinary: bin,
        rawHex: binaryToHex(bin),
        evenParityValid: false,
        oddParityValid: false,
        isValid: false,
        errorMessage: 'Input must contain at least 34 bits',
      );
    }

    int pEven = int.parse(bin[0]);
    int fcOnes = countOnes(bin, 1, 17);
    bool evenValid = ((pEven + fcOnes) % 2 == 0);

    int pOdd = int.parse(bin[33]);
    int cnOnes = countOnes(bin, 17, 33);
    bool oddValid = ((pOdd + cnOnes) % 2 == 1);

    int fc = int.parse(bin.substring(1, 17), radix: 2);
    int cn = int.parse(bin.substring(17, 33), radix: 2);

    return WiegandResult(
      format: WiegandFormat.wiegand34,
      facilityCode: fc,
      cardNumber: cn,
      rawBinary: bin,
      rawHex: binaryToHex(bin),
      evenParityValid: evenValid,
      oddParityValid: oddValid,
      isValid: evenValid && oddValid,
    );
  }

  /// Encode Standard 34-bit Wiegand
  static WiegandResult encode34Bit(int facilityCode, int cardNumber) {
    int fc = facilityCode.clamp(0, 65535);
    int cn = cardNumber.clamp(0, 65535);

    String fcBin = fc.toRadixString(2).padLeft(16, '0');
    String cnBin = cn.toRadixString(2).padLeft(16, '0');
    String data32 = fcBin + cnBin;

    int pEven = (countOnes(data32, 0, 16) % 2 == 0) ? 0 : 1;
    int pOdd = (countOnes(data32, 16, 32) % 2 == 0) ? 1 : 0;

    String bin = '$pEven$data32$pOdd';

    return WiegandResult(
      format: WiegandFormat.wiegand34,
      facilityCode: fc,
      cardNumber: cn,
      rawBinary: bin,
      rawHex: binaryToHex(bin),
      evenParityValid: true,
      oddParityValid: true,
      isValid: true,
    );
  }

  /// Decode 37-bit Wiegand (H10304 format: 16-bit FC, 19-bit Card Number)
  /// [0]       Even parity for bits 1..18
  /// [1..16]   Facility Code (16 bits)
  /// [17..35]  Card Number (19 bits)
  /// [36]      Odd parity for bits 18..35
  static WiegandResult decode37BitH10304(String input) {
    String bin = normalizeToBinary(input, targetBits: 37);
    if (bin.length > 37) {
      bin = bin.substring(bin.length - 37);
    }
    if (bin.length < 37) {
      return WiegandResult(
        format: WiegandFormat.wiegand37H10304,
        facilityCode: 0,
        cardNumber: 0,
        rawBinary: bin,
        rawHex: binaryToHex(bin),
        evenParityValid: false,
        oddParityValid: false,
        isValid: false,
        errorMessage: 'Input must contain at least 37 bits',
      );
    }

    int pEven = int.parse(bin[0]);
    int firstHalfOnes = countOnes(bin, 1, 19);
    bool evenValid = ((pEven + firstHalfOnes) % 2 == 0);

    int pOdd = int.parse(bin[36]);
    int secondHalfOnes = countOnes(bin, 18, 36);
    bool oddValid = ((pOdd + secondHalfOnes) % 2 == 1);

    int fc = int.parse(bin.substring(1, 17), radix: 2);
    int cn = int.parse(bin.substring(17, 36), radix: 2);

    return WiegandResult(
      format: WiegandFormat.wiegand37H10304,
      facilityCode: fc,
      cardNumber: cn,
      rawBinary: bin,
      rawHex: binaryToHex(bin),
      evenParityValid: evenValid,
      oddParityValid: oddValid,
      isValid: evenValid && oddValid,
    );
  }

  /// Encode 37-bit Wiegand (H10304)
  static WiegandResult encode37BitH10304(int facilityCode, int cardNumber) {
    int fc = facilityCode.clamp(0, 65535);
    int cn = cardNumber.clamp(0, 524287); // 19 bits max

    String fcBin = fc.toRadixString(2).padLeft(16, '0');
    String cnBin = cn.toRadixString(2).padLeft(19, '0');
    String data35 = fcBin + cnBin; // bits 1..35

    // Bit 0: even parity over bits 1..18 -> data35[0..18]
    int pEven = (countOnes(data35, 0, 18) % 2 == 0) ? 0 : 1;
    // Bit 36: odd parity over bits 18..35 -> data35[17..35]
    int pOdd = (countOnes(data35, 17, 35) % 2 == 0) ? 1 : 0;

    String bin = '$pEven$data35$pOdd';

    return WiegandResult(
      format: WiegandFormat.wiegand37H10304,
      facilityCode: fc,
      cardNumber: cn,
      rawBinary: bin,
      rawHex: binaryToHex(bin),
      evenParityValid: true,
      oddParityValid: true,
      isValid: true,
    );
  }

  /// Auto-detects best format by bit length or tries 26-bit default.
  static WiegandResult autoDecode(String input) {
    String bin = normalizeToBinary(input);
    if (bin.length >= 37) {
      return decode37BitH10304(bin);
    } else if (bin.length >= 34) {
      return decode34Bit(bin);
    } else {
      return decode26Bit(bin);
    }
  }
}
