import 'package:chameleonultragui/gui/component/card_button.dart';
import 'package:chameleonultragui/gui/component/error_message.dart';
import 'package:chameleonultragui/gui/menu/pages/dump_editor.dart';
import 'package:chameleonultragui/gui/page/read_card.dart';
import 'package:chameleonultragui/helpers/general.dart';
import 'package:chameleonultragui/helpers/mifare_ultralight/general.dart';
import 'package:chameleonultragui/helpers/mifare_ultralight/security.dart';
import 'package:chameleonultragui/helpers/validators.dart';
import 'package:chameleonultragui/main.dart';
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
  /// Populated after every successful read; drives the leak-recovery panel.
  MifareUltralightSecurity? security;

  /// Whether the last completed read authenticated with a user-supplied key.
  bool lastReadUsedPassword = false;

  Future<void> readCard({bool withPassword = false}) async {
    var appState = Provider.of<ChameleonGUIState>(context, listen: false);
    var localizations = AppLocalizations.of(context)!;
    Uint8List? pack;
    setState(() {
      cardData = [];
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
      if (pageData.isNotEmpty) {
        cardData.add(Uint8List.fromList(pageData.slice(0, 4).toList()));
      } else {
        cardData.add(Uint8List(0));
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
            // Security configuration analysis (method 1+2): report what the
            // read revealed about password protection, and when the PWD page
            // was readable without a key, offer one-tap unlock.
            if (security != null) ...[
              const SizedBox(height: 8),
              _SecurityAnalysisPanel(
                  security: security!,
                  readWithPassword: lastReadUsedPassword,
                  onUnlock: readCardWithRecoveredPassword),
              const SizedBox(height: 8),
            ],
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

/// Shows what the keyless read revealed about the tag's password
/// configuration (AUTH0 / PROT / CFGLCK) and, when the PWD page was readable
/// in the clear, offers to unlock the full memory with the recovered key.
class _SecurityAnalysisPanel extends StatelessWidget {
  final MifareUltralightSecurity security;
  final bool readWithPassword;
  final Future<void> Function() onUnlock;

  const _SecurityAnalysisPanel({
    required this.security,
    required this.readWithPassword,
    required this.onUnlock,
  });

  @override
  Widget build(BuildContext context) {
    final localizations = AppLocalizations.of(context)!;
    final appState = Provider.of<ChameleonGUIState>(context, listen: false);

    // A password read already implies the config pages are readable, so a
    // recovered key is only newsworthy when we did *not* authenticate.
    final leaked =
        security.passwordLeaked && !readWithPassword;
    final protectedFrom = security.protectedFrom;

    final String status = leaked
        ? localizations.ultralight_analysis_leaked
        : protectedFrom == null
            ? localizations.ultralight_analysis_open
            : localizations.ultralight_analysis_protected(protectedFrom);

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            Row(children: [
              Icon(leaked
                  ? Icons.key
                  : protectedFrom == null
                      ? Icons.lock_open
                      : Icons.lock_outline),
              const SizedBox(width: 8),
              Expanded(
                  child: Text(localizations.ultralight_security_analysis,
                      style: Theme.of(context).textTheme.titleSmall)),
            ]),
            const SizedBox(height: 8),
            Text(status),
            const SizedBox(height: 4),
            if (security.configLocked)
              Text(localizations.ultralight_analysis_config_locked),
            if (security.authLimit > 0)
              Text(localizations
                  .ultralight_analysis_auth_limit(security.authLimit)),
            if (leaked) ...[
              const SizedBox(height: 8),
              Text(localizations.ultralight_analysis_pwd_value(
                  security.leakedPasswordHex ?? "")),
              if (security.leakedPackHex != null)
                Text(localizations.ultralight_analysis_pack_value(
                    security.leakedPackHex!)),
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
