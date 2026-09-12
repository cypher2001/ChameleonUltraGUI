import 'dart:typed_data';

import 'package:chameleonultragui/connector/serial_abstract.dart';
import 'package:chameleonultragui/generated/i18n/app_localizations.dart';
import 'package:chameleonultragui/helpers/definitions.dart';
import 'package:chameleonultragui/helpers/general.dart';
import 'package:chameleonultragui/helpers/mifare_classic/general.dart';
import 'package:chameleonultragui/helpers/mifare_classic/key_check_batched.dart';
import 'package:chameleonultragui/main.dart';
import 'package:chameleonultragui/recovery/recovery.dart';
import 'package:chameleonultragui/sharedprefsprovider.dart';

// Recovery
import 'package:chameleonultragui/recovery/recovery.dart' as recovery;

extension PartitionList<E> on List<E> {
  List<List<E>> partition(int size) {
    assert(size > 0);
    final out = <List<E>>[];
    for (var i = 0; i < length; i += size) {
      final end = i + size < length ? i + size : length;
      out.add(sublist(i, end));
    }
    return out;
  }
}

enum ChameleonKeyCheckmark { none, found, checking, disabled }

class MifareClassicRecovery {
  late ChameleonGUIState appState;
  late AppLocalizations localizations;
  String error;
  String state;
  bool allKeysExists;
  List<Dictionary> dictionaries;
  Dictionary? selectedDictionary;
  List<ChameleonKeyCheckmark> checkMarks;
  List<Uint8List> validKeys;
  List<Uint8List> cardData;
  double dumpProgress;
  double? hardnestedProgress;
  double? keyCheckProgress;
  void Function() update;
  MifareClassicType mifareClassicType;
  bool isMifareClassicEV1;

  /// Live activity text from the native hardnested worker ("Brute force
  /// phase: 12.34%", "Checking bitflip properties..."), shown under the
  /// progress bar while an attack runs.
  String hardnestedActivity = "";

  /// True while an async hardnested attack is running on the native worker.
  bool hardnestedRunning = false;

  /// Set from the UI to ask the running hardnested attack to stop.
  bool hardnestedCancelRequested = false;

  MifareClassicRecovery(
      {required this.appState,
      required this.update,
      required this.localizations,
      this.error = '',
      this.state = '',
      this.allKeysExists = false,
      this.dictionaries = const [],
      this.dumpProgress = 0,
      this.selectedDictionary,
      this.mifareClassicType = MifareClassicType.none,
      this.isMifareClassicEV1 = false,
      List<ChameleonKeyCheckmark>? checkMarks,
      List<Uint8List>? validKeys,
      List<Uint8List>? cardData})
      : checkMarks =
            checkMarks ?? List.generate(80, (_) => ChameleonKeyCheckmark.none),
        validKeys = validKeys ?? List.generate(80, (_) => Uint8List(0)),
        cardData = cardData ?? List.generate(256, (_) => Uint8List(0)) {
    initializeEV1();
  }

  Future<bool> checkKeysOnSector(
      List<Uint8List> keys, int keyType, int sector) async {
    state = localizations.checking_keys(keys.length);
    Uint8List? key;
    keyCheckProgress = null;
    int chunkSize =
        appState.connector!.connectionType == ConnectionType.ble ? 32 : 64;

    if (getSectorState(sector, keyType) != ChameleonKeyCheckmark.found &&
        getSectorState(sector, keyType) != ChameleonKeyCheckmark.disabled) {
      setCheckingSector(sector, keyType);
      int totalChunks = keys.partition(chunkSize).length;

      for (var chunk in keys.partition(chunkSize)) {
        key = await appState.communicator!.mf1AuthMultipleKeys(
            mfClassicGetSectorTrailerBlockBySector(sector),
            0x60 + keyType,
            chunk);
        if (key != null) {
          setKeyAsFound(sector, keyType, key);
          keyCheckProgress = null;
          await recheckKey(key, sector);
          return true;
        } else if (totalChunks > 10) {
          keyCheckProgress = (keyCheckProgress ?? 0) + 1 / totalChunks;
          update();
        }
      }

      if (key == null) {
        setMissingSector(sector, keyType);
      }
    }

    if (keyType == 0 &&
        getSectorState(sector, 0) == ChameleonKeyCheckmark.found &&
        getSectorState(sector, 1) != ChameleonKeyCheckmark.found &&
        getSectorState(sector, 1) != ChameleonKeyCheckmark.disabled &&
        key != null) {
      Uint8List block = await appState.communicator!.mf1ReadBlock(
          mfClassicGetSectorTrailerBlockBySector(sector), 0x60 + keyType, key);
      if (block.length == 16) {
        Uint8List bKey = block.sublist(10);
        if (bytesToHex(bKey) != bytesToHex(Uint8List(6))) {
          keyCheckProgress = null;
          await recheckKey(key, sector);
          return true;
        }
      }
    }

    setMissingSector(sector, keyType);
    keyCheckProgress = null;
    return false;
  }

  Future<void> initialize() async {
    if (!await appState.communicator!.isReaderDeviceMode()) {
      await appState.communicator!.setReaderDeviceMode(true);
    }

    var mifare = await appState.communicator!.detectMf1Support();

    if (mifare) {
      mifareClassicType = await mfClassicGetType(appState.communicator!);
    } else {
      appState.log!.e("Not Mifare Classic tag!");
    }

    isMifareClassicEV1 =
        await appState.communicator!.mf1Auth(0x45, 0x61, gMifareClassicKeys[3]);
    initializeEV1();
  }

  Future<void> recheckKey(Uint8List key, int startingSector) async {
    for (var sector = startingSector;
        sector <
            mfClassicGetSectorCount(mifareClassicType,
                isEV1: isMifareClassicEV1);
        sector++) {
      for (var keyType = 0; keyType < 2; keyType++) {
        if (getSectorState(sector, keyType) == ChameleonKeyCheckmark.none) {
          state = localizations.checking_keys(1);
          appState.log!.d(
              "Checking found key ${bytesToHex(key)} on sector $sector, key type $keyType");
          setCheckingSector(sector, keyType);

          if (await appState.communicator!.mf1Auth(
              mfClassicGetSectorTrailerBlockBySector(sector),
              0x60 + keyType,
              key)) {
            // Found valid key
            setKeyAsFound(sector, keyType, key);
          } else {
            setMissingSector(sector, keyType);
          }

          update();
        }
      }
    }
  }

  void initializeEV1() {
    if (isMifareClassicEV1) {
      setKeyAsFound(16, 0, gMifareClassicKeys[4]); // MFC EV1 SIGNATURE 16 A
      setKeyAsFound(16, 1, gMifareClassicKeys[5]); // MFC EV1 SIGNATURE 16 B
      setKeyAsFound(17, 0, gMifareClassicKeys[6]); // MFC EV1 SIGNATURE 17 A
      setKeyAsFound(17, 1, gMifareClassicKeys[3]); // MFC EV1 SIGNATURE 17 B
    }
  }

  Future<void> checkKeys({bool skipDefaultDictionary = false}) async {
    initializeEV1();

    final sectorCount = mfClassicGetSectorCount(mifareClassicType,
        isEV1: isMifareClassicEV1);

    // Batched path: one round trip per key chunk across ALL sectors at once
    // (cmd 2012). Falls back to the legacy per-sector loop only when the
    // firmware lacks cmd 2012 support. Both paths leave identical state
    // behind (found keys set, unmatched slots back to none), so downstream
    // recovery/dump is unchanged. Errors (e.g. tag removed mid-sweep)
    // propagate to the UI's existing error handler.
    bool batched = false;
    try {
      batched = await appState.communicator!.supportsMf1CheckKeysOfSectors();
    } catch (_) {}

    if (batched) {
      await checkKeysBatched(
          sectorCount: sectorCount,
          skipDefaultDictionary: skipDefaultDictionary);
      computeAllKeysExists(sectorCount);
      state = "";
      update();
      return;
    }

    for (var sector = 0; sector < sectorCount; sector++) {
      List<Uint8List> keyList = [
        ...selectedDictionary!.keys,
        if (!skipDefaultDictionary)
          ...gMifareClassicKeys
              .where((key) => !selectedDictionary!.keys.contains(key))
      ];

      for (var keyType = 0; keyType < 2; keyType++) {
        await checkKeysOnSector(keyList, keyType, sector);
      }
    }

    computeAllKeysExists(sectorCount);
    state = "";
    update();
  }

  /// Batched multi-sector dictionary check (cmd 2012).
  ///
  /// Sends the key list in chunks; each chunk is tried against every
  /// not-yet-found (sector, key type) slot in a single round trip. The
  /// firmware deduplicates keys and auto-reads Key B from the sector trailer
  /// whenever a Key A match allows it. Chunk size and per-call timeout follow
  /// the RRG reference client (`chameleon_cli_unit.check_keys`): worst-case
  /// auth count is keys × unmasked slots, budgeted at 0.1 s per auth.
  Future<void> checkKeysBatched({
    required int sectorCount,
    bool skipDefaultDictionary = false,
  }) async {
    if (selectedDictionary == null) return;

    // Merge dictionary + default keys exactly like the legacy path.
    final keySet = <String, Uint8List>{};
    for (final key in selectedDictionary!.keys) {
      keySet[bytesToHex(key)] = key;
    }
    if (!skipDefaultDictionary) {
      for (final key in gMifareClassicKeys) {
        keySet.putIfAbsent(bytesToHex(key), () => key);
      }
    }
    final keys = keySet.values.toList();
    if (keys.isEmpty) return;

    // Slots we still need a key for: not found, not disabled, within the
    // card's sector count. Firmware only iterates 40 sectors; skipping the
    // rest keeps nonexistent trailer blocks untouched.
    final checkedSlots = <int>[];
    for (var sector = 0; sector < sectorCount; sector++) {
      for (var keyType = 0; keyType < 2; keyType++) {
        if (getSectorState(sector, keyType) == ChameleonKeyCheckmark.none) {
          checkedSlots.add(mfClassicKeySlot(sector, keyType));
        }
      }
    }
    if (checkedSlots.isEmpty) return;

    // Mark every slot we will attempt as "checking" for live UI feedback.
    for (final slot in checkedSlots) {
      setCheckingSector(slot >> 1, slot & 1);
    }
    update();

    // 20 keys per call keeps worst-case auth time bounded and matches the
    // RRG reference client. (The old per-sector path sent 32/64 keys to a
    // single block; here every key is tried against every remaining slot, so
    // a smaller chunk with an adaptive timeout is the correct trade-off.)
    const int chunkSize = 20;

    var mask = buildCheckKeysOfSectorsMask(checkedSlots);
    int bitsToCheck = checkedSlots.length;

    var chunkIndex = 0;
    for (var i = 0; i < keys.length && bitsToCheck > 0; i += chunkSize) {
      chunkIndex++;
      final end = i + chunkSize > keys.length ? keys.length : i + chunkSize;
      final chunk = keys.sublist(i, end);

      // Worst-case budget: each key is tried against each still-unmasked
      // slot (~0.1 s per auth), plus 1 s base, mirroring the reference CLI.
      final timeout = Duration(
          milliseconds: (1000 + bitsToCheck * chunk.length * 100).round());

      try {
        final found = await appState.communicator!
            .mf1CheckKeysOfSectors(mask, chunk, timeout: timeout);

        // The firmware already sweeps every key in this chunk against every
        // unmasked slot in one call, so no per-key re-propagation is needed.
        for (final entry in found.entries) {
          final slot = entry.key;
          final sector = slot >> 1;
          final keyType = slot & 1;
          if (sector >= sectorCount) continue;
          setKeyAsFound(sector, keyType, entry.value);
        }

        // Rebuild the mask from live state so slots found in this chunk are
        // skipped (mask bit set) in later chunks.
        final remaining = _unfoundSlots(sectorCount);
        bitsToCheck = remaining.length;
        mask = buildCheckKeysOfSectorsMask(remaining);
        if (bitsToCheck == 0) {
          break;
        }
      } catch (e) {
        // Tag removed mid-sweep: reset any "checking" marks and rethrow so
        // the caller surfaces the error and the UI resets to a sane state.
        for (final slot in checkedSlots) {
          setMissingSector(slot >> 1, slot & 1);
        }
        rethrow;
      }

      final totalChunks = (keys.length / chunkSize).ceil();
      if (totalChunks > 10) {
        keyCheckProgress = chunkIndex / totalChunks;
      }
      state = localizations.checking_keys(keys.length - end);
      update();
    }

    // Unmatched slots: back to "none" so downstream recovery knows the
    // dictionary was exhausted for them.
    for (final slot in checkedSlots) {
      final state = getSectorState(slot >> 1, slot & 1);
      if (state == ChameleonKeyCheckmark.checking) {
        setMissingSector(slot >> 1, slot & 1);
      }
    }
    keyCheckProgress = null;
    update();
  }

  List<int> _unfoundSlots(int sectorCount) {
    final slots = <int>[];
    for (var sector = 0; sector < sectorCount; sector++) {
      for (var keyType = 0; keyType < 2; keyType++) {
        if (getSectorState(sector, keyType) == ChameleonKeyCheckmark.none) {
          slots.add(mfClassicKeySlot(sector, keyType));
        }
      }
    }
    return slots;
  }

  void computeAllKeysExists(int sectorCount) {
    allKeysExists = true;
    for (var sector = 0; sector < sectorCount; sector++) {
      for (var keyType = 0; keyType < 2; keyType++) {
        if (getSectorState(sector, keyType) != ChameleonKeyCheckmark.found &&
            getSectorState(sector, keyType) != ChameleonKeyCheckmark.disabled) {
          allKeysExists = false;
        }
      }
    }
  }

  Future<void> recoverKeys() async {
    state = localizations.checking_card_info;
    update();

    error = "";
    bool hasKey = false;
    bool hasBackdoor = await mfClassicHasBackdoor(appState.communicator!);
    (int, NestedNonces, NestedNonces, Uint8List)? backdoorInfo;
    if (hasBackdoor) {
      backdoorInfo = await appState.communicator!
          .getMf1StaticEncryptedNestedAcquire(
              sectorCount: mfClassicGetSectorCount(mifareClassicType,
                  isEV1: isMifareClassicEV1));
    }

    DarksideResult darkside = DarksideResult.fixed;
    for (var sector = 0;
        sector <
                mfClassicGetSectorCount(mifareClassicType,
                    isEV1: isMifareClassicEV1) &&
            !hasKey;
        sector++) {
      for (var keyType = 0; keyType < 2; keyType++) {
        if (getSectorState(sector, keyType) == ChameleonKeyCheckmark.found) {
          hasKey = true;
          break;
        }
      }
    }

    update();

    bool isStaticEncrypted = false;

    if (hasBackdoor) {
      isStaticEncrypted = await mfClassicIsStaticEncrypted(
          appState.communicator!, 0, 4, backdoorInfo!.$4);
    }

    NTLevel prng = await appState.communicator!.getMf1NTLevel();
    update();

    if (!hasKey && !isStaticEncrypted && prng != NTLevel.static) {
      state = localizations.checking_or_running_darkside;
      update();

      try {
        setCheckingSector(0, 1);
        darkside = await appState.communicator!.checkMf1Darkside();
      } catch (_) {
        setMissingSector(0, 1);
      }

      if (darkside == DarksideResult.vulnerable) {
        // recover with darkside
        var data =
            await appState.communicator!.getMf1Darkside(0x03, 0x61, true, 15);
        var darkside = DarksideDart(uid: data.uid, items: []);
        bool found = false;
        update();

        for (var tries = 0; tries < 5 && !found; tries++) {
          darkside.items.add(DarksideItemDart(
              nt1: data.nt1,
              ks1: data.ks1,
              par: data.par,
              nr: data.nr,
              ar: data.ar));

          var keys = await recovery.darkside(darkside);
          if (keys.isNotEmpty) {
            appState.log!.d("Darkside: Found keys: $keys. Checking them...");

            if (await checkKeysOnSector(mfClassicConvertKeys(keys), 1, 0)) {
              found = true;
              hasKey = true;

              break;
            }
          } else {
            appState.log!.d("Can't find keys, retrying...");
            data = await appState.communicator!
                .getMf1Darkside(0x03, 0x61, false, 15);
          }
        }

        if (!found) {
          setMissingSector(0, 1);
        }
      }
    }

    update();

    if (!hasKey && hasBackdoor && prng == NTLevel.weak && !isStaticEncrypted) {
      state = localizations.backdoor_recovery_of_non_static_encrypted;
      setCheckingSector(0, 0);

      for (var i = 0; i < 3; i++) {
        NTDistance distance = await appState.communicator!
            .getMf1NTDistance(0, 0x64, backdoorInfo!.$4);

        NestedNonces nonces = await appState.communicator!
            .getMf1NestedNonces(0, 0x64, backdoorInfo.$4, 0, 0x60, level: prng);

        var nested = NestedDart(
            uid: distance.uid,
            distance: distance.distance,
            nt0: nonces.nonces[0].nt,
            nt0Enc: nonces.nonces[0].ntEnc,
            par0: nonces.nonces[0].parity,
            nt1: nonces.nonces[1].nt,
            nt1Enc: nonces.nonces[1].ntEnc,
            par1: nonces.nonces[1].parity);

        List<int> keys = await recovery.nested(nested);

        if (keys.isNotEmpty) {
          appState.log!.d("Found keys: $keys. Checking them...");
          if (await checkKeysOnSector(mfClassicConvertKeys(keys), 0, 0)) {
            break;
          }
        }
      }
    }

    Uint8List validKey = Uint8List(0);
    int validKeyBlock = 0;
    int validKeyType = -1;

    for (var sector = 0;
        sector <
            mfClassicGetSectorCount(mifareClassicType,
                isEV1: isMifareClassicEV1);
        sector++) {
      for (var keyType = 0; keyType < 2; keyType++) {
        if (getSectorState(sector, keyType) == ChameleonKeyCheckmark.found) {
          validKey = getSectorKey(sector, keyType);
          validKeyBlock = mfClassicGetSectorTrailerBlockBySector(sector);
          validKeyType = keyType;
          if (!isStaticEncrypted) {
            isStaticEncrypted = await mfClassicIsStaticEncrypted(
                appState.communicator!, validKeyBlock, validKeyType, validKey);
          }
          break;
        }
      }
    }

    if ((isStaticEncrypted || (validKeyType == -1 && hasBackdoor)) &&
        backdoorInfo != null) {
      prng = NTLevel.backdoor;
    }

    if (validKeyType == -1 && prng != NTLevel.backdoor) {
      error = localizations.recovery_error_no_keys_darkside;
      state = "";
      return;
    }

    int tries = [NTLevel.backdoor, NTLevel.static].contains(prng) ? 1 : 5;

    for (var sector = 0;
        sector <
            mfClassicGetSectorCount(mifareClassicType,
                isEV1: isMifareClassicEV1);
        sector++) {
      for (var keyType = 0; keyType < 2; keyType++) {
        if (getSectorState(sector, keyType) == ChameleonKeyCheckmark.none) {
          String attackType;

          switch (prng) {
            case NTLevel.static:
              attackType = "Static Nested";
            case NTLevel.weak:
              attackType = "Nested";
            case NTLevel.hard:
              attackType = "Hard Nested";
            case NTLevel.backdoor:
              attackType = localizations.has_backdoor_support;
            case NTLevel.unknown:
              attackType = "";
          }

          state = localizations.collecting_nonces(attackType);
          setCheckingSector(sector, keyType);

          NTDistance? distance;
          NestedNonces? nonces;

          if (prng != NTLevel.backdoor) {
            distance = await appState.communicator!
                .getMf1NTDistance(validKeyBlock, 0x60 + validKeyType, validKey);
          }

          bool found = false;
          for (var i = 0; i < tries && !found; i++) {
            List<int> keys = [];

            if (prng == NTLevel.hard) {
              hardnestedRunning = true;
              hardnestedProgress = 0;
              hardnestedCancelRequested = false;
              hardnestedActivity = "";
              update();

              try {
                var result = await collectHardnestedNonces(
                    validKeyBlock,
                    0x60 + validKeyType,
                    validKey,
                    mfClassicGetSectorTrailerBlockBySector(sector),
                    0x60 + keyType);

                if (result is String) {
                  hardnestedRunning = false;
                  hardnestedProgress = null;
                  setMissingSector(sector, keyType);
                  error = result;
                  return;
                } else {
                  nonces = result as NestedNonces;
                }
              } on recovery.HardnestedCancelledException {
                // User pressed cancel during nonce collection.
                hardnestedRunning = false;
                hardnestedActivity = "";
                hardnestedProgress = null;
                setMissingSector(sector, keyType);
                state = "";
                update();
                error = localizations.hardnested_cancelled;
                return;
              }
            } else if (prng != NTLevel.backdoor) {
              nonces = await appState.communicator!.getMf1NestedNonces(
                  validKeyBlock,
                  0x60 + validKeyType,
                  validKey,
                  mfClassicGetSectorTrailerBlockBySector(sector),
                  0x60 + keyType,
                  level: prng);
            }

            state = localizations.recovering_key(attackType);
            update();

            if (prng == NTLevel.weak) {
              var nested = NestedDart(
                  uid: distance!.uid,
                  distance: distance.distance,
                  nt0: nonces!.nonces[0].nt,
                  nt0Enc: nonces.nonces[0].ntEnc,
                  par0: nonces.nonces[0].parity,
                  nt1: nonces.nonces[1].nt,
                  nt1Enc: nonces.nonces[1].ntEnc,
                  par1: nonces.nonces[1].parity);

              keys = await recovery.nested(nested);
            } else if (prng == NTLevel.static) {
              var nested = StaticNestedDart(
                uid: distance!.uid,
                keyType: 0x60 + validKeyType,
                nt0: nonces!.nonces[0].nt,
                nt0Enc: nonces.nonces[0].ntEnc,
                nt1: nonces.nonces[1].nt,
                nt1Enc: nonces.nonces[1].ntEnc,
              );

              keys = await recovery.staticNested(nested);
            } else if (prng == NTLevel.hard) {
              var nested =
                  HardNestedDart(nonces: nonces!.getHardNested(distance!.uid));

              // Run on the native worker thread with live progress and a
              // cooperative cancel, instead of a blind blocking FFI call.
              hardnestedRunning = true;
              hardnestedCancelRequested = false;
              hardnestedActivity = "";
              hardnestedProgress = null;
              update();

              await recovery.hardNestedStartAsync(nested);

              bool cancelled = false;
              try {
                int recovered = await recovery.hardNestedAwait(
                  onProgress: (progress) {
                    hardnestedActivity = progress.activity;
                    // Determinate bar only during brute force; bitflip /
                    // candidate stages render as indeterminate (null).
                    hardnestedProgress = progress.stage ==
                            recovery.HardnestedStageDart.bruteforce
                        ? progress.progress
                        : null;
                    update();
                  },
                  isCancelRequested: () => hardnestedCancelRequested,
                );
                keys = recovered != 0 ? [recovered] : [];
              } on recovery.HardnestedCancelledException {
                cancelled = true;
              }

              hardnestedRunning = false;
              hardnestedActivity = "";
              hardnestedProgress = null;

              if (cancelled) {
                // User pressed cancel: stop the whole recovery run, keep the
                // keys found so far, and let the UI show the cancel message.
                setMissingSector(sector, keyType);
                state = "";
                update();
                error = localizations.hardnested_cancelled;
                return;
              }
            } else if (prng == NTLevel.backdoor) {
              setCheckingSector(sector, 1);

              var possibleAKeys = await recovery.staticEncryptedNested(
                  StaticEncryptedNestedDart(
                      uid: backdoorInfo!.$1,
                      nt: backdoorInfo.$2.nonces[sector].nt,
                      ntEnc: backdoorInfo.$2.nonces[sector].ntEnc,
                      ntParEnc: backdoorInfo.$2.nonces[sector].parity));

              var possibleBKeys = await recovery.staticEncryptedNested(
                  StaticEncryptedNestedDart(
                      uid: backdoorInfo.$1,
                      nt: backdoorInfo.$3.nonces[sector].nt,
                      ntEnc: backdoorInfo.$3.nonces[sector].ntEnc,
                      ntParEnc: backdoorInfo.$3.nonces[sector].parity));

              var filtered = await StaticEncryptedKeysFilterAsync.filterKeys(
                  possibleAKeys,
                  possibleBKeys,
                  backdoorInfo.$2.nonces[sector].nt,
                  backdoorInfo.$3.nonces[sector].nt);

              if (checkMarks[sector + 40] != ChameleonKeyCheckmark.found &&
                  checkMarks[sector + 40] != ChameleonKeyCheckmark.disabled &&
                  await checkKeysOnSector(
                      mfClassicConvertKeys(filtered.$2.reversed.toList()),
                      1,
                      sector)) {
                checkMarks[sector + 40] = ChameleonKeyCheckmark.found;
              }

              if (checkMarks[sector] == ChameleonKeyCheckmark.found ||
                  checkMarks[sector] == ChameleonKeyCheckmark.disabled) {
                found = true;
                break;
              } else if (await checkKeysOnSector(
                  mfClassicConvertKeys(
                      await StaticEncryptedKeysFilterAsync.findMatchingKeys(
                          backdoorInfo.$3.nonces[sector].nt,
                          bytesToU64(Uint8List.fromList(
                              [0, 0, ...validKeys[sector + 40]])),
                          backdoorInfo.$2.nonces[sector].nt,
                          possibleAKeys)),
                  0,
                  sector)) {
                found = true;
                break;
              } else if (await checkKeysOnSector(
                  mfClassicConvertKeys(filtered.$1.reversed.toList()),
                  0,
                  sector)) {
                found = true;
                break;
              }

              setMissingSector(sector, 0);
              setMissingSector(sector, 1);
            }

            if (keys.isNotEmpty) {
              appState.log!.d("Found keys: $keys. Checking them...");

              if (await checkKeysOnSector(
                  mfClassicConvertKeys(keys), keyType, sector)) {
                found = true;

                break;
              }
            } else {
              appState.log!.e("Can't find keys, retrying...");
            }
          }
        }
      }
    }

    state = "";
    allKeysExists = true;
    for (var sector = 0;
        sector <
            mfClassicGetSectorCount(mifareClassicType,
                isEV1: isMifareClassicEV1);
        sector++) {
      for (var keyType = 0; keyType < 2; keyType++) {
        if (getSectorState(sector, keyType) != ChameleonKeyCheckmark.found &&
            getSectorState(sector, keyType) != ChameleonKeyCheckmark.disabled) {
          allKeysExists = false;
        }
      }
    }
    update();
  }

  Future<void> dumpData() async {
    cardData = List.generate(256, (_) => Uint8List(0));

    for (var sector = 0;
        sector <
            mfClassicGetSectorCount(mifareClassicType,
                isEV1: isMifareClassicEV1);
        sector++) {
      for (var block = 0;
          block < mfClassicGetBlockCountBySector(sector);
          block++) {
        for (var keyType = 0; keyType < 2; keyType++) {
          appState.log!
              .d("Dumping sector $sector, block $block with key $keyType");

          if (getSectorKey(sector, keyType).isEmpty) {
            appState.log!.w("Skipping missing key");
            cardData[block + mfClassicGetFirstBlockCountBySector(sector)] =
                Uint8List(16);
            continue;
          }

          var blockData = await appState.communicator!.mf1ReadBlock(
              block + mfClassicGetFirstBlockCountBySector(sector),
              0x60 + keyType,
              getSectorKey(sector, keyType));

          if (blockData.isEmpty) {
            if (keyType == 1) {
              blockData = Uint8List(16);
            } else {
              continue;
            }
          }

          if (mfClassicGetSectorTrailerBlockBySector(sector) ==
              block + mfClassicGetFirstBlockCountBySector(sector)) {
            // set keys in sector trailer
            if (getSectorKey(sector, 0).isNotEmpty) {
              blockData.setRange(0, 6, getSectorKey(sector, 0));
            }

            if (getSectorKey(sector, 1).isNotEmpty) {
              blockData.setRange(10, 16, getSectorKey(sector, 1));
            }
          }

          cardData[block + mfClassicGetFirstBlockCountBySector(sector)] =
              blockData;

          dumpProgress = (block + mfClassicGetFirstBlockCountBySector(sector)) /
              (mfClassicGetBlockCount(mifareClassicType,
                  isEV1: isMifareClassicEV1));

          update();

          break;
        }
      }
    }
  }

  Future<dynamic> collectHardnestedNonces(int block, int keyType,
      Uint8List knownKey, int targetBlock, int targetKeyType) async {
    NestedNonces nonces = NestedNonces(nonces: []);
    while (true) {
      var collectedNonces = await appState.communicator!.getMf1NestedNonces(
          block, keyType, knownKey, targetBlock, targetKeyType,
          level: NTLevel.hard);
      nonces.nonces.addAll(collectedNonces.nonces);
      List info = nonces.getNoncesInfo();
      appState.log!.d(
          "Collected ${nonces.nonces.length} nonces, sum ${info[0]}, num ${info[1]}");

      if (nonces.nonces.isEmpty) {
        return localizations.recovery_old_firmware;
      }

      hardnestedProgress = info[1] / 256;
      state = localizations.hardnested_collecting_nonces(
          (hardnestedProgress! * 256).toInt().toString());
      update();
      if (hardnestedCancelRequested) {
        throw const recovery.HardnestedCancelledException();
      }
      if (info[1] == 256) {
        if ([
          0,
          32,
          56,
          64,
          80,
          96,
          104,
          112,
          120,
          128,
          136,
          144,
          152,
          160,
          176,
          192,
          200,
          224,
          256
        ].contains(info[0])) {
          break;
        }

        appState.log!.e("Got wrong sum, trying to collect nonces again...");
        nonces.nonces = [];
      }
    }

    hardnestedProgress = null;
    return nonces;
  }

  void setKeyAsFound(int sector, int keyType, Uint8List key) {
    checkMarks[sector + (keyType * 40)] = ChameleonKeyCheckmark.found;
    validKeys[sector + (keyType * 40)] = key;
    update();
  }

  /// Asks the running hardnested attack (if any) to stop. The native worker
  /// checks the flag between work items and the recovery loop then reports
  /// the cancel through the UI state.
  void cancelHardnested() {
    hardnestedCancelRequested = true;
    update();
  }

  void setCheckingSector(int sector, int keyType) {
    if (getSectorState(sector, keyType) == ChameleonKeyCheckmark.none) {
      checkMarks[sector + (keyType * 40)] = ChameleonKeyCheckmark.checking;
    }
    update();
  }

  void setMissingSector(int sector, int keyType) {
    if (getSectorState(sector, keyType) == ChameleonKeyCheckmark.checking) {
      checkMarks[sector + (keyType * 40)] = ChameleonKeyCheckmark.none;
      update();
    }
  }

  Uint8List getSectorKey(int sector, int keyType) {
    return validKeys[sector + (keyType * 40)];
  }

  ChameleonKeyCheckmark getSectorState(int sector, int keyType) {
    return checkMarks[sector + (keyType * 40)];
  }
}
