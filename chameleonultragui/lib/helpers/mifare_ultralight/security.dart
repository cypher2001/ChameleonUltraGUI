import 'dart:typed_data';

import 'package:chameleonultragui/bridge/chameleon.dart';
import 'package:chameleonultragui/helpers/definitions.dart';
import 'package:chameleonultragui/helpers/mifare_ultralight/general.dart';

/// Result of analyzing the configuration pages of a password-protected
/// MIFARE Ultralight EV1 / NTAG21x tag.
///
/// The layout follows the NXP memory map used by the pm3 `hf mfu` tooling:
/// the four trailing pages hold  cfg0 (AUTH0 ...), cfg1 (ACCESS ...), PWD
/// and PACK. AUTH0 is byte 3 of cfg0; cfg1 byte 0 packs PROT (bit 7),
/// CFGLCK (bit 6), NFC_CNT_EN (bit 4), NFC_CNT_PWD_PROT (bit 3) and
/// AUTHLIM (bits 0-2).
class MifareUltralightSecurity {
  /// The type this configuration was read from.
  final TagType type;

  /// Raw cfg0 page (4 bytes), when readable without authentication.
  final Uint8List? cfg0;

  /// Raw cfg1 page (4 bytes), when readable without authentication.
  final Uint8List? cfg1;

  /// Raw PWD page (4 bytes), when readable without authentication.
  final Uint8List? pwd;

  /// Raw PACK page (4 bytes), when readable without authentication.
  final Uint8List? pack;

  /// Page index from which authentication is required (AUTH0).
  final int auth0;

  /// True when read *and* write of the protected area need the password.
  /// False means only write is protected (reads are open).
  final bool readProtected;

  /// True when the configuration area is permanently locked (CFGLCK).
  final bool configLocked;

  /// True when the NFC counter is enabled (NFC_CNT_EN).
  final bool nfcCounterEnabled;

  /// True when the NFC counter is password protected (NFC_CNT_PWD_PROT).
  final bool nfcCounterPasswordProtected;

  /// Maximum allowed password attempts (AUTHLIM, 0 = unlimited).
  final int authLimit;

  MifareUltralightSecurity({
    required this.type,
    this.cfg0,
    this.cfg1,
    this.pwd,
    this.pack,
    required this.auth0,
    required this.readProtected,
    required this.configLocked,
    required this.nfcCounterEnabled,
    required this.nfcCounterPasswordProtected,
    required this.authLimit,
  });

  /// Page count of [type] (0 when unknown/unmapped).
  int get pageCount => mfUltralightGetPagesCount(type);

  /// Index of the first protected page, or null when no page is protected
  /// (factory default AUTH0 = 0xFF or out of range).
  int? get protectedFrom => auth0 < pageCount ? auth0 : null;

  /// True when the password was recoverable from the unprotected memory
  /// (AUTH0 never set / out of range, or PROT = 0 so reads stay open), i.e.
  /// the PWD page of the tag is readable without authenticating.
  bool get passwordLeaked => pwd != null && pwd!.length == 4;

  /// The recovered 4-byte password (big-endian display form), when leaked.
  String? get leakedPasswordHex {
    if (!passwordLeaked || pwd == null) {
      return null;
    }
    return pwd!.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  /// The recovered 2-byte PACK, when its page was readable too.
  String? get leakedPackHex {
    if (pack == null || pack!.length < 2) {
      return null;
    }
    return pack!
        .sublist(0, 2)
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join();
  }

  /// Index of the cfg0 page, or null when this tag type has no password
  /// config (plain Ultralight / Ultralight C use different schemes).
  static int? configStartPage(TagType type) {
    final pwdPage = mfUltralightGetPasswordPage(type);
    if (pwdPage == 0) {
      // Plain Ultralight has no PWD; UL-C uses 3DES (page 0 placeholder).
      return null;
    }
    return pwdPage - 2; // cfg0 sits two pages before PWD.
  }

  /// Reads the four configuration pages of [type] without authenticating.
  ///
  /// Returns null when the tag type has no password configuration, or when
  /// the config pages can not be read (read-protected: PROT = 1 with AUTH0
  /// set, or the tag vanished).
  static Future<MifareUltralightSecurity?> readFromCard(
      ChameleonCommunicator communicator, TagType type) async {
    final start = configStartPage(type);
    if (start == null) {
      return null;
    }

    final pages = <Uint8List>[];
    for (var i = 0; i < 4; i++) {
      final page = start + i;
      final Uint8List resp;
      try {
        resp = await communicator.send14ARaw(
          Uint8List.fromList([0x30, page]),
          checkResponseCrc: false,
          keepRfField: i < 3,
        );
      } catch (_) {
        return null;
      }
      if (resp.length < 4) {
        // NACK / no response: config area is read protected.
        return null;
      }
      pages.add(Uint8List.fromList(resp.sublist(0, 4)));
    }

    return parse(type, pages[0], pages[1], pages[2], pages[3]);
  }

  /// Parses the four trailing config pages (cfg0, cfg1, PWD, PACK).
  ///
  /// [cfg0] carries AUTH0 in its last byte; [cfg1] carries the ACCESS byte
  /// in its first byte.
  static MifareUltralightSecurity parse(TagType type, Uint8List cfg0,
      Uint8List cfg1, Uint8List pwd, Uint8List pack) {
    final access = cfg1.isNotEmpty ? cfg1[0] : 0;
    return MifareUltralightSecurity(
      type: type,
      cfg0: cfg0,
      cfg1: cfg1,
      pwd: pwd,
      pack: pack,
      auth0: cfg0.length >= 4 ? cfg0[3] : 0xFF,
      readProtected: (access & 0x80) != 0,
      configLocked: (access & 0x40) != 0,
      nfcCounterEnabled: (access & 0x10) != 0,
      nfcCounterPasswordProtected: (access & 0x08) != 0,
      authLimit: access & 0x07,
    );
  }
}
