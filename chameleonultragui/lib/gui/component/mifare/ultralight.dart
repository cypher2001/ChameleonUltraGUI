import 'package:chameleonultragui/gui/component/card_button.dart';
import 'package:chameleonultragui/gui/component/error_message.dart';
import 'package:chameleonultragui/gui/menu/pages/dump_editor.dart';
import 'package:chameleonultragui/gui/page/read_card.dart';
import 'package:chameleonultragui/helpers/general.dart';
import 'package:chameleonultragui/helpers/definitions.dart';
import 'package:chameleonultragui/helpers/mifare_ultralight/general.dart';
import 'package:chameleonultragui/helpers/mifare_ultralight/pwdgen.dart';
import 'package:chameleonultragui/helpers/mifare_ultralight/security.dart';
import 'package:chameleonultragui/helpers/validators.dart';
import 'package:chameleonultragui/main.dart';
import 'package:chameleonultragui/gui/menu/tools/hf_sniffing.dart';
import 'package:chameleonultragui/sharedprefsprovider.dart';
import 'package:collection/collection.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

// Localizations
import 'package:chameleonultragui/generated/i18n/app_localizations.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

enum MifareUltralightState { none, read, save }

class MifareUltralightHelper extends StatefulWidget {
  final HFCardInfo hfInfo;
  final bool allowSave;

  const MifareUltralightHelper(
      {super.key, required this.hfInfo, this.allowSave = true});

  @override
  State<StatefulWidget> createState() => CardReaderState();
}

class CardReaderState extends State<MifareUltralightHelper> {
  TextEditingController keyController = TextEditingController();
  MifareUltralightState state = MifareUltralightState.none;
  final GlobalKey<FormState> formKey = GlobalKey<FormState>();
  List<Uint8List> cardData = [];
  String version = "";
  String signature = "";
  List<int> counters = [];
  String dumpName = "";
  String error = "";
  double progress = -1;

  /// Result of the read-only security configuration analysis (method 1+2).
  /// Null means the config area could not be read without a key (read
  /// protection active), the tag has no password config (plain UL / UL-C),
  /// or the analysis was skipped.
  MifareUltralightSecurity? security;

  /// Page indices that returned no data during the last keyless read.
  /// Non-empty means the keyless dump is incomplete: those pages are either
  /// read-protected (password required) or beyond the configured AUTH0
  /// boundary. The save-state panel reports them.
  List<int> unreadablePages = [];

  /// Whether the last completed read authenticated with a user-supplied key.
  bool lastReadUsedPassword = false;

  /// True while a password sweep (defaults / dictionary / pwdgen) runs.
  bool dictionaryRunning = false;

  /// True once a sweep has run to exhaustion without finding the password -
  /// switches the panel into "next step: sniff a real reader" guidance.
  bool dictionaryFailed = false;

  /// Index into the merged candidate list for the sweep progress.
  int dictionaryIndex = 0;

  /// Dictionaries holding 4-byte keys (seeded + user-editable), shown as a
  /// dropdown next to the sweep button.
  List<Dictionary> ulDictionaries = [];

  /// Currently selected user dictionary id, or null for built-ins only.
  String? selectedDictionaryId;

  Future<void> readCard({bool withPassword = false}) async {
    var appState = Provider.of<ChameleonGUIState>(context, listen: false);
    var localizations = AppLocalizations.of(context)!;
    Uint8List? pack;
    setState(() {
      cardData = [];
      unreadablePages = [];
      error = "";
      state = MifareUltralightState.read;
    });

    for (var page = 0;
        page < mfUltralightGetPagesCount(widget.hfInfo.type);
        page++) {
      if (withPassword) {
        pack = await appState.communicator!.send14ARaw(
            Uint8List.fromList([0x1B, ...hexToBytes(keyController.text)]),
            keepRfField: true);
        if (pack.length < 2) {
          setState(() {
            state = MifareUltralightState.none;
            error = localizations.invalid_password;
          });
          return;
        }
      }

      Uint8List pageData = await appState.communicator!
          .send14ARaw(Uint8List.fromList([0x30, page]));
      if (pageData.length >= 4) {
        cardData.add(Uint8List.fromList(pageData.slice(0, 4).toList()));
      } else {
        // Empty / NACK response: page is read-protected (no key), not
        // present, or the read genuinely failed. Record it so the UI can
        // tell the user the dump is incomplete.
        cardData.add(Uint8List(0));
        if (!withPassword) {
          unreadablePages.add(page);
        }
      }

      setState(() {
        progress = page / mfUltralightGetPagesCount(widget.hfInfo.type);
      });
    }

    bool hasValidData = false;
    for (var block in cardData) {
      if (block.isNotEmpty) {
        hasValidData = true;
      }
    }

    if (!hasValidData) {
      setState(() {
        progress = 0;
        cardData = [];
        error = localizations.failed_to_read_block;
        state = MifareUltralightState.none;
      });
      return;
    }

    version =
        bytesToHexSpace(await mfUltralightGetVersion(appState.communicator!));
    signature =
        bytesToHexSpace(await mfUltralightGetSignature(appState.communicator!));

    if (mfUltralightHasCounters(widget.hfInfo.type)) {
      counters = await mfUltralightReadAllCountersFromCard(
          appState.communicator!, widget.hfInfo.type);
    }

    // Save password to dump if was used
    int passwordPage = mfUltralightGetPasswordPage(widget.hfInfo.type);
    if (passwordPage != 0 && withPassword) {
      cardData[passwordPage] = hexToBytes(keyController.text);
      cardData[passwordPage + 1] = Uint8List(4);
      for (var byte = 0; byte < pack!.length; byte++) {
        cardData[passwordPage + 1][byte] = pack[byte];
      }
    }

    // Method 1+2: read the security configuration (AUTH0/PROT/PWD/PACK)
    // without authenticating. When the PWD page is readable in the clear we
    // can offer one-tap unlock; otherwise we still surface what is (and is
    // not) actually protected.
    MifareUltralightSecurity? sec;
    if (MifareUltralightSecurity.configStartPage(widget.hfInfo.type) != null) {
      sec = await MifareUltralightSecurity.readFromCard(
          appState.communicator!, widget.hfInfo.type);
    }

    setState(() {
      error = "";
      state = MifareUltralightState.save;
      security = sec;
      lastReadUsedPassword = withPassword;
      dictionaryFailed = false;
      // Refresh the editable 4-byte dictionary list for the sweep dropdown.
      ulDictionaries = appState.sharedPreferencesProvider
          .getMifareUltralightDictionaries();
      if (selectedDictionaryId == null && ulDictionaries.isNotEmpty) {
        selectedDictionaryId = ulDictionaries.first.id;
      }
    });
  }

  /// Re-reads the card using a password recovered from the unprotected
  /// configuration pages (one-tap unlock from the leak panel).
  Future<void> readCardWithRecoveredPassword() async {
    final pwd = security?.leakedPasswordHex;
    if (pwd == null) {
      return;
    }
    keyController.text = pwd;
    await readCard(withPassword: true);
  }

  /// Retries the read under a manually-chosen tag type. Used when detection
  /// misidentified a protected NTAG21x / UL-EV1 as a plain Ultralight (the
  /// panel shows the warning).
  Future<void> retryReadAs(TagType type) async {
    widget.hfInfo.type = type;
    final localizations = AppLocalizations.of(context);
    if (localizations != null) {
      widget.hfInfo.tech = chameleonTagToString(type, localizations);
    }
    setState(() {
      security = null;
      unreadablePages = [];
      lastReadUsedPassword = false;
      error = "";
    });
    await readCard(withPassword: false);
  }

  /// Sweeps candidate passwords against the tag: UID-derived pwdgen
  /// algorithms first (cheap, targeted), then the built-in default list,
  /// then the selected user dictionary (if any). Each attempt re-powers the
  /// field (send14ARaw default) so the tag's failed-auth counter resets -
  /// NTAG21x/EV1 stop answering PWD_AUTH after a few consecutive failures
  /// until the next power cycle.
  Future<void> tryPasswords() async {
    var appState = Provider.of<ChameleonGUIState>(context, listen: false);
    if (appState.communicator == null) {
      return;
    }

    // Load the user dictionary (4-byte keys) if one is selected.
    final userDictKeys = <String>[];
    if (selectedDictionaryId != null) {
      for (final dict in ulDictionaries) {
        if (dict.id == selectedDictionaryId) {
          for (final key in dict.keys) {
            userDictKeys.add(bytesToHex(key).toUpperCase());
          }
        }
      }
    }

    final candidates = mifareUltralightMergeCandidates(
      widget.hfInfo.uid.replaceAll(' ', ''),
      defaults: kMifareUltralightDefaultPasswords,
      dictionary: userDictKeys,
    );

    setState(() {
      dictionaryRunning = true;
      dictionaryFailed = false;
      dictionaryIndex = 0;
      error = "";
    });

    for (var i = 0; i < candidates.length; i++) {
      final pwd = candidates[i];
      setState(() {
        dictionaryIndex = i;
      });

      final pack = await mfuTryPassword(appState.communicator!, pwd);
      if (pack != null) {
        // Password accepted: PACK returned. Re-read with the found key.
        keyController.text = pwd;
        if (mounted) {
          setState(() {
            dictionaryRunning = false;
          });
        }
        await readCard(withPassword: true);
        return;
      }
    }

    if (mounted) {
      final localizations = AppLocalizations.of(context);
      setState(() {
        dictionaryRunning = false;
        dictionaryFailed = true;
        error = localizations?.ultralight_dictionary_failed ??
            "dictionary_failed";
      });
    }
  }

  Future<void> saveCard({bool bin = false}) async {
    var appState = Provider.of<ChameleonGUIState>(context, listen: false);

    List<int> cardDump = [];
    var localizations = AppLocalizations.of(context)!;
    for (var page = 0;
        page < mfUltralightGetPagesCount(widget.hfInfo.type);
        page++) {
      if (cardData[page].isEmpty) {
        cardDump.addAll(Uint8List(4));
      } else {
        cardDump.addAll(cardData[page]);
      }
    }

    if (bin) {
      await FilePicker.saveFile(
        dialogTitle: '${localizations.output_file}:',
        fileName: '${widget.hfInfo.uid.replaceAll(" ", "")}.bin',
        bytes: Uint8List.fromList(cardDump),
      );
    } else {
      var tags = appState.sharedPreferencesProvider.getCards();
      tags.add(CardSave(
          uid: widget.hfInfo.uid,
          sak: hexToBytes(widget.hfInfo.sak)[0],
          atqa: hexToBytes(widget.hfInfo.atqa),
          name: dumpName,
          tag: widget.hfInfo.type,
          data: cardData,
          extraData: CardSaveExtra(
            ultralightSignature: hexToBytes(signature),
            ultralightVersion: hexToBytes(version),
            ultralightCounters: counters,
          ),
          ats: (widget.hfInfo.ats != localizations.no)
              ? hexToBytes(widget.hfInfo.ats)
              : Uint8List(0)));
      appState.sharedPreferencesProvider.setCards(tags);
    }
  }

  Future<void> viewDump() async {
    var localizations = AppLocalizations.of(context)!;
    final viewCard = CardSave(
      uid: widget.hfInfo.uid,
      sak: hexToBytes(widget.hfInfo.sak)[0],
      atqa: hexToBytes(widget.hfInfo.atqa),
      name: dumpName,
      tag: widget.hfInfo.type,
      data: cardData,
      extraData: CardSaveExtra(
        ultralightSignature: hexToBytes(signature),
        ultralightVersion: hexToBytes(version),
        ultralightCounters: counters,
      ),
      ats: (widget.hfInfo.ats != localizations.no)
          ? hexToBytes(widget.hfInfo.ats)
          : Uint8List(0),
    );

    await showDialog(
      context: context,
      builder: (context) => DumpEditor(
        cardSave: viewCard,
        onSave: (data) {
          // Keep edits in memory so both save options use the modified dump.
          cardData = data;
        },
      ),
    );

    if (mounted) {
      setState(() {});
    }
  }

  @override
  Widget build(BuildContext context) {
    var appState = Provider.of<ChameleonGUIState>(context, listen: false);
    var localizations = AppLocalizations.of(context)!;

    return Column(
      children: [
        const SizedBox(height: 16),
        if (state == MifareUltralightState.none) ...[
          Form(
            key: formKey,
            autovalidateMode: AutovalidateMode.onUserInteraction,
            child: TextFormField(
              controller: keyController,
              decoration: InputDecoration(
                  labelText: localizations.key,
                  hintMaxLines: 4,
                  hintText: localizations
                      .enter_something(localizations.ultralight_key_prompt)),
              inputFormatters: hexFormatter,
              validator: (value) => validateHex(value, localizations,
                  exactBytes: 4, fieldName: localizations.key),
            ),
          ),
          const SizedBox(height: 8),
          Row(children: [
            Expanded(
              child: TextButton(
                onPressed: () async => {await readCard(withPassword: true)},
                child: Text(localizations.read_with_key),
              ),
            ),
            Expanded(
              child: TextButton(
                onPressed: () async => {await readCard(withPassword: false)},
                child: Text(localizations.read_without_key),
              ),
            ),
          ]),
        ],
        if (error != "") ...[
          const SizedBox(height: 16),
          ErrorMessage(errorMessage: error),
        ],
        if (state == MifareUltralightState.read) ...[
          LinearProgressIndicator(value: progress),
          const SizedBox(height: 8)
        ],
        if (state == MifareUltralightState.save)
          Center(
              child: Column(children: [
            // Security/coverage analysis (method 1+2): always shown after a
            // read so the user learns (a) whether the keyless dump is
            // complete, and (b) what password protection the tag has - and
            // gets a one-tap unlock when the PWD page was readable.
            const SizedBox(height: 8),
            _SecurityAnalysisPanel(
                type: widget.hfInfo.type,
                security: security,
                unreadablePages: unreadablePages,
                readWithPassword: lastReadUsedPassword,
                dictionaryRunning: dictionaryRunning,
                dictionaryFailed: dictionaryFailed,
                dictionaryIndex: dictionaryIndex,
                candidateTotal: mifareUltralightMergeCandidates(
                  widget.hfInfo.uid.replaceAll(' ', ''),
                  defaults: kMifareUltralightDefaultPasswords,
                  dictionary: [
                    for (final d in ulDictionaries)
                      if (d.id == selectedDictionaryId)
                        for (final k in d.keys) bytesToHex(k).toUpperCase()
                  ],
                ).length,
                ulDictionaries: ulDictionaries,
                selectedDictionaryId: selectedDictionaryId,
                onDictionaryChanged: (id) {
                  setState(() {
                    selectedDictionaryId = id;
                  });
                },
                onUnlock: readCardWithRecoveredPassword,
                onRetryAs: retryReadAs,
                onTryPasswords: tryPasswords),
            const SizedBox(height: 8),
            Wrap(
                alignment: WrapAlignment.center,
                spacing: 8,
                runSpacing: 8,
                children: [
                  ElevatedButton(
                    onPressed: viewDump,
                    style: customCardButtonStyle(appState),
                    child: Text(localizations.view_dump),
                  ),
                  ElevatedButton(
                    onPressed: () async {
                      await showDialog(
                        context: context,
                        builder: (BuildContext context) {
                          return AlertDialog(
                            title: Text(localizations.enter_name_of_card),
                            content: TextField(
                              onChanged: (value) {
                                setState(() {
                                  dumpName = value;
                                });
                              },
                            ),
                            actions: [
                              ElevatedButton(
                                onPressed: () async {
                                  await saveCard();
                                  if (context.mounted) {
                                    Navigator.pop(context);
                                  }
                                },
                                child: Text(localizations.ok),
                              ),
                              ElevatedButton(
                                onPressed: () {
                                  Navigator.pop(
                                      context); // Close the modal without saving
                                },
                                child: Text(localizations.cancel),
                              ),
                            ],
                          );
                        },
                      );
                    },
                    style: customCardButtonStyle(appState),
                    child: Text(localizations.save),
                  ),
                  ElevatedButton(
                    onPressed: () async {
                      await saveCard(bin: true);
                    },
                    style: customCardButtonStyle(appState),
                    child: Text(localizations.save_as(".bin")),
                  ),
                ]),
          ])),
    ],
  );
}
}

/// Password-capable UL-family types a misdetected tag may really be.
/// A protected tag NACKs the marker-page probes, so the heuristic detector
/// falls back to plain "Ultralight"; these are the plausible real types.
const List<TagType> _retryCandidateTypes = [
  TagType.ntag210,
  TagType.ntag212,
  TagType.ntag213,
  TagType.ntag215,
  TagType.ntag216,
  TagType.ultralight21,
];

/// Reports, after a read, whether the dump is complete and what password
/// protection the tag has. Always visible in the save state.
///
/// - Plain Ultralight: no password system at all - every page is readable,
///   the dump is complete by construction.
/// - Ultralight C: 3DES authentication - the PWD-page model does not apply.
/// - EV1/NTAG with readable config: AUTH0 / PROT / CFGLCK decoded; when the
///   PWD page was readable without a key, offers one-tap unlock.
/// - EV1/NTAG with read-protected config: reports that pages could not be
///   read and a password (or sniffing) is required.
class _SecurityAnalysisPanel extends StatelessWidget {
  final TagType type;
  final MifareUltralightSecurity? security;
  final List<int> unreadablePages;
  final bool readWithPassword;
  final bool dictionaryRunning;
  final bool dictionaryFailed;
  final int dictionaryIndex;
  final int candidateTotal;
  final List<Dictionary> ulDictionaries;
  final String? selectedDictionaryId;
  final Future<void> Function() onUnlock;
  final Future<void> Function(TagType) onRetryAs;
  final Future<void> Function() onTryPasswords;
  final ValueChanged<String?> onDictionaryChanged;

  const _SecurityAnalysisPanel({
    required this.type,
    required this.security,
    required this.unreadablePages,
    required this.readWithPassword,
    required this.dictionaryRunning,
    required this.dictionaryFailed,
    required this.dictionaryIndex,
    required this.candidateTotal,
    required this.ulDictionaries,
    required this.selectedDictionaryId,
    required this.onUnlock,
    required this.onRetryAs,
    required this.onTryPasswords,
    required this.onDictionaryChanged,
  });

  /// "1-3, 5, 8-9" style summary of a page index list.
  static String pageRanges(List<int> pages) {
    if (pages.isEmpty) {
      return "-";
    }
    final sorted = [...pages]..sort();
    final parts = <String>[];
    var start = sorted.first;
    var prev = sorted.first;
    for (var i = 1; i < sorted.length; i++) {
      if (sorted[i] == prev + 1) {
        prev = sorted[i];
        continue;
      }
      parts.add(start == prev ? '$start' : '$start-$prev');
      start = sorted[i];
      prev = sorted[i];
    }
    parts.add(start == prev ? '$start' : '$start-$prev');
    return parts.join(", ");
  }

  @override
  Widget build(BuildContext context) {
    final localizations = AppLocalizations.of(context)!;
    final appState = Provider.of<ChameleonGUIState>(context, listen: false);

    // Coverage: which pages of the nominal map came back empty.
    final totalPages = mfUltralightGetPagesCount(type);
    final readableCount = totalPages - unreadablePages.length;
    final incomplete = !readWithPassword && unreadablePages.isNotEmpty;

    // Does this tag type even have the 0x1B password scheme?
    final hasPasswordConfig =
        MifareUltralightSecurity.configStartPage(type) != null;
    final bool isPlainUl = type == TagType.ultralight;

    String status;
    String? detail;
    IconData icon;
    var showUnlock = false;
    String? pwdValue;
    String? packValue;

    // A plain Ultralight physically cannot read-protect pages. If the app
    // detected "plain UL" but pages came back empty, the type detection is
    // almost certainly wrong (a protected NTAG21x / UL-EV1 masquerading as
    // plain UL because its AUTH0 hides the marker pages). Flag it.
    final misdetected =
        isPlainUl && incomplete && unreadablePages.isNotEmpty;

    if (misdetected) {
      icon = Icons.warning_amber;
      status = localizations.ultralight_analysis_maybe_misdetected;
      detail = localizations.ultralight_analysis_pages_missing(
          readableCount, totalPages);
    } else if (!hasPasswordConfig) {
      // Plain UL / UL-C: no PWD-page analysis applies.
      icon = Icons.info_outline;
      if (isPlainUl) {
        status = localizations.ultralight_analysis_no_password_system;
      } else {
        // Ultralight C uses 3DES, not the EV1/NTAG PWD scheme.
        status = localizations.ultralight_analysis_ulc_3des;
      }
      detail = incomplete
          ? localizations.ultralight_analysis_pages_missing(
              readableCount, totalPages)
          : null;
    } else if (security == null) {
      // Config pages could not be read without a key: read protection on.
      icon = Icons.lock_outline;
      status = localizations.ultralight_analysis_config_read_protected;
      if (incomplete) {
        detail = localizations.ultralight_analysis_pages_missing(
            readableCount, totalPages);
      }
    } else {
      // security != null here (null handled in the branch above).
      final sec = security!;
      final leaked = sec.passwordLeaked && !readWithPassword;
      final protectedFrom = sec.protectedFrom;
      icon = leaked
          ? Icons.key
          : protectedFrom == null
              ? Icons.lock_open
              : Icons.lock_outline;

      status = leaked
          ? localizations.ultralight_analysis_leaked
          : protectedFrom == null
              ? localizations.ultralight_analysis_open
              : localizations.ultralight_analysis_protected(protectedFrom);

      if (incomplete) {
        detail = localizations.ultralight_analysis_pages_missing(
            readableCount, totalPages);
      }
      showUnlock = leaked;
      pwdValue = sec.leakedPasswordHex;
      packValue = sec.leakedPackHex;
    }

    final subtitle = (incomplete && detail != null)
        ? detail
        : (!readWithPassword &&
                !incomplete &&
                !hasPasswordConfig &&
                isPlainUl)
            ? localizations.ultralight_analysis_all_read(totalPages)
            : detail;

    final sec = security;
    final configLocked = sec?.configLocked ?? false;
    final authLimit = sec?.authLimit ?? 0;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            Row(children: [
              Icon(icon),
              const SizedBox(width: 8),
              Expanded(
                  child: Text(localizations.ultralight_security_analysis,
                      style: Theme.of(context).textTheme.titleSmall)),
            ]),
            const SizedBox(height: 8),
            Text(status),
            if (subtitle != null) ...[
              const SizedBox(height: 4),
              Text(subtitle),
            ],
            if (configLocked)
              Text(localizations.ultralight_analysis_config_locked),
            if (authLimit > 0)
              Text(localizations.ultralight_analysis_auth_limit(authLimit)),
            // Which pages failed (fix A) - always shown when incomplete.
            if (incomplete) ...[
              const SizedBox(height: 4),
              Text(localizations.ultralight_analysis_unreadable_pages(
                  pageRanges(unreadablePages))),
            ],
            // Misdetection recovery (fix B): offer plausible protected types.
            if (misdetected) ...[
              const SizedBox(height: 8),
              Wrap(
                  spacing: 6,
                  runSpacing: 6,
                  children: _retryCandidateTypes
                      .map((candidate) => OutlinedButton(
                            onPressed: () => onRetryAs(candidate),
                            style: OutlinedButton.styleFrom(
                                visualDensity: VisualDensity.compact),
                            child: Text(chameleonTagToString(
                                candidate, localizations)),
                          ))
                      .toList()),
            ],
            // Recovery path (enhancement 3): on a password-capable tag we
            // cannot read without a key, spell out the three escalating
            // steps so the operator always knows where they are.
            if (hasPasswordConfig && !readWithPassword && !showUnlock) ...[
              const SizedBox(height: 10),
              Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: Theme.of(context)
                      .colorScheme
                      .surfaceContainerHighest
                      .withValues(alpha: 0.4),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      localizations.ultralight_analysis_recovery_path,
                      style: Theme.of(context)
                          .textTheme
                          .titleSmall
                          ?.copyWith(fontWeight: FontWeight.bold),
                    ),
                    const SizedBox(height: 6),
                    Text(localizations.ultralight_analysis_step_pwdgen),
                    const SizedBox(height: 2),
                    Text(localizations.ultralight_analysis_step_dictionary),
                    const SizedBox(height: 2),
                    Text(localizations.ultralight_analysis_step_sniff),
                  ],
                ),
              ),
            ],
            // Password sweep (methods 2+3): pwdgen from UID + defaults + the
            // selected user dictionary - for password-capable tags whose config
            // could not be read without a key.
            if (hasPasswordConfig && !readWithPassword && !showUnlock) ...[
              const SizedBox(height: 8),
              if (dictionaryRunning)
                Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text(localizations.ultralight_analysis_dictionary_running(
                      dictionaryIndex + 1, candidateTotal)),
                  const SizedBox(height: 4),
                  LinearProgressIndicator(
                      value: candidateTotal == 0
                          ? null
                          : (dictionaryIndex + 1) / candidateTotal),
                ])
              else ...[
                if (ulDictionaries.isNotEmpty) ...[
                  DropdownButton<String>(
                    isExpanded: true,
                    value: selectedDictionaryId ?? '',
                    hint: Text(localizations.ultralight_analysis_dictionary_hint),
                    items: [
                      DropdownMenuItem<String>(
                        value: '',
                        child:
                            Text(localizations.ultralight_analysis_builtin_only),
                      ),
                      for (final d in ulDictionaries)
                        DropdownMenuItem<String>(
                          value: d.id,
                          child: Text(
                              '${d.name} (${d.keys.length} keys)'),
                        ),
                    ],
                    onChanged: (id) {
                      // The '' sentinel maps back to null (built-ins only).
                      onDictionaryChanged(id == '' ? null : id);
                    },
                  ),
                  const SizedBox(height: 4),
                ],
                OutlinedButton.icon(
                  onPressed: onTryPasswords,
                  icon: const Icon(Icons.try_sms_star_outlined),
                  label: Text(localizations.ultralight_analysis_try_passwords),
                ),
              ],
            ],
            // Enhancement 1: sweep exhausted -> guide to the one attack that
            // actually works on a custom-PWD tag (sniff a legitimate read).
            if (hasPasswordConfig && dictionaryFailed && !readWithPassword) ...[
              const SizedBox(height: 10),
              Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: Theme.of(context)
                      .colorScheme
                      .errorContainer
                      .withValues(alpha: 0.35),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      localizations.ultralight_analysis_custom_pwd,
                      style: Theme.of(context)
                          .textTheme
                          .titleSmall
                          ?.copyWith(fontWeight: FontWeight.bold),
                    ),
                    const SizedBox(height: 4),
                    Text(localizations.ultralight_analysis_sniff_explain),
                    const SizedBox(height: 8),
                    ElevatedButton.icon(
                      onPressed: () => showDialog(
                        context: context,
                        builder: (_) => const HfSniffingMenu(),
                      ),
                      icon: const Icon(Icons.radar),
                      label: Text(localizations.ultralight_open_sniffer),
                    ),
                  ],
                ),
              ),
            ],
            if (showUnlock) ...[
              const SizedBox(height: 8),
              Text(localizations.ultralight_analysis_pwd_value(pwdValue ?? "")),
              if (packValue != null)
                Text(localizations.ultralight_analysis_pack_value(packValue)),
              const SizedBox(height: 4),
              ElevatedButton.icon(
                onPressed: onUnlock,
                style: customCardButtonStyle(appState),
                icon: const Icon(Icons.lock_open),
                label: Text(localizations.ultralight_analysis_unlock),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
