import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:localgatekeys/core/crypto.dart';
import 'package:localgatekeys/core/csv_import.dart';
import 'package:localgatekeys/core/models.dart';
import 'package:localgatekeys/core/password_tools.dart';
import 'package:localgatekeys/core/security_report.dart';
import 'package:localgatekeys/core/totp.dart';
import 'package:localgatekeys/core/vault_store.dart';
import 'package:localgatekeys/state/vault_controller.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('crypto', () {
    test('seal/open round trip and tamper detection', () async {
      final key = VaultCrypto.randomBytes(32);
      final sealed = await VaultCrypto.seal(key, utf8.encode('secret'), 'aad');
      expect(utf8.decode(await VaultCrypto.open(key, sealed, 'aad')), 'secret');
      await expectLater(VaultCrypto.open(key, sealed, 'other'), throwsA(isA<VaultAuthError>()));
      final tampered = Uint8List.fromList(sealed)..[30] ^= 1;
      await expectLater(VaultCrypto.open(key, tampered, 'aad'), throwsA(isA<VaultAuthError>()));
      await expectLater(
          VaultCrypto.open(VaultCrypto.randomBytes(32), sealed, 'aad'), throwsA(isA<VaultAuthError>()));
    });

    test('large blobs use the isolate path', () async {
      final key = VaultCrypto.randomBytes(32);
      final data = VaultCrypto.randomBytes(600 * 1024);
      final sealed = await VaultCrypto.sealLarge(key, data, 'blob');
      expect(await VaultCrypto.openLarge(key, sealed, 'blob'), data);
    });

    test('recovery code normalisation', () {
      final code = VaultCrypto.newRecoveryCode();
      expect(code, matches(RegExp(r'^[0-9A-Z]{5}(-[0-9A-Z]{5}){4}$')));
      expect(VaultCrypto.normalizeRecoveryCode(code.toLowerCase().replaceAll('-', ' ')),
          VaultCrypto.normalizeRecoveryCode(code));
      expect(VaultCrypto.normalizeRecoveryCode('o0-il1'), '00111');
    });
  });

  group('totp', () {
    // RFC 6238 appendix B, SHA-1, 8 digits.
    final secret = utf8.encode('12345678901234567890');
    test('RFC 6238 vectors', () async {
      final cases = {59: '94287082', 1111111109: '07081804', 1234567890: '89005924', 2000000000: '69279037'};
      for (final e in cases.entries) {
        expect(await generateHotp(secret, e.key ~/ 30, digits: 8), e.value);
      }
    });

    test('parses otpauth links and base32', () {
      final c = TotpConfig.parse(
          'otpauth://totp/GitHub:alex?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub&digits=8');
      expect(c!.digits, 8);
      expect(c.issuer, 'GitHub');
      expect(c.secret, secret);
      expect(TotpConfig.parse('gezd gnbv gy3t qojq gezd gnbv gy3t qojq')!.secret, secret);
      expect(TotpConfig.parse('not a secret!'), isNull);
    });
  });

  group('password tools', () {
    test('generator honours options', () {
      for (var i = 0; i < 50; i++) {
        final p = generatePassword(const GeneratorOptions(length: 24));
        expect(p.length, 24);
        expect(p, matches(RegExp('[a-z]')));
        expect(p, matches(RegExp('[A-Z]')));
        expect(p, matches(RegExp('[0-9]')));
        expect(p, isNot(matches(RegExp('[Il1O0o]'))));
      }
      final digitsOnly = generatePassword(
          const GeneratorOptions(length: 8, upper: false, lower: false, symbols: false));
      expect(digitsOnly, matches(RegExp(r'^[2-9]{8}$')));
    });

    test('strength', () {
      expect(strengthOf('password'), Strength.veryWeak);
      expect(strengthOf('aaaaaaaaaaaa').isWeak, isTrue);
      expect(strengthOf(generatePassword(const GeneratorOptions(length: 20))), Strength.veryStrong);
    });
  });

  test('CSV import handles Chrome and Bitwarden exports', () {
    final chrome = loginsFromCsv('name,url,username,password,note\r\n'
        'GitHub,https://github.com,alex,"pa,ss""word",\r\n'
        ',https://www.example.com/login,me,x,hello\n');
    expect(chrome, hasLength(2));
    expect(chrome.first.field('password'), 'pa,ss"word');
    expect(chrome.last.title, 'example.com');
    expect(chrome.last.notes, 'hello');

    final bitwarden = loginsFromCsv(
        'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n'
        ',,login,Steam,,,,https://store.steampowered.com,alex_p,hunter2,JBSWY3DPEHPK3PXP\n');
    expect(bitwarden.single.field('totp'), 'JBSWY3DPEHPK3PXP');
    expect(() => loginsFromCsv('a,b\n1,2\n'), throwsFormatException);
  });

  test('security report flags weak, reused and expiring items', () {
    VaultItem login(String title, String password) =>
        VaultItem.create(ItemType.login)..title = title..fields['password'] = password;
    final passport = VaultItem.create(ItemType.identity)
      ..fields['expires'] = DateTime.now().add(const Duration(days: 20)).toIso8601String().substring(0, 10);
    final items = [login('a', 'password'), login('b', 'Zq8!vR2#kL9@xW4m'), login('c', 'Zq8!vR2#kL9@xW4m'), passport];
    final r = SecurityReport.build(items, VaultSettings(), hasRecoveryCode: true);
    expect(r.weak, hasLength(1));
    expect(r.reusedCount, 2);
    expect(r.expiring.single.item, passport);
    expect(r.backupOverdue, isTrue);
    expect(r.score, lessThan(50));
  });

  group('vault controller', () {
    late Directory dir;
    setUp(() async => dir = await Directory.systemTemp.createTemp('lgk_test'));
    tearDown(() async => dir.delete(recursive: true));

    test('create, lock, unlock, recover, attachments, backup', () async {
      final c = VaultController(VaultStore(dir));
      await c.init();
      expect(c.status, VaultStatus.noVault);
      final code = await c.createVault('correct horse battery');

      final item = VaultItem.create(ItemType.login)
        ..title = 'Steam'
        ..fields['password'] = 'one';
      final doc = await c.storeAttachment('scan.png', Uint8List.fromList([1, 2, 3]));
      item.attachments.add(doc);
      await c.saveItem(item);

      final edited = c.byId(item.id)!.copy()..fields['password'] = 'two';
      await c.saveItem(edited);
      expect(c.byId(item.id)!.passwordHistory.single.value, 'one');

      // Nothing readable on disk.
      final raw = await File('${dir.path}/vault.lgk').readAsString();
      expect(raw, isNot(contains('Steam')));

      c.lock();
      expect(c.allItems, isEmpty);
      expect(await c.unlock('wrong'), isNotNull);
      expect(await c.unlock('correct horse battery'), isNull);
      expect(c.byId(item.id)!.field('password'), 'two');
      expect(await c.readAttachment(c.byId(item.id)!.attachments.single), [1, 2, 3]);

      c.lock();
      expect(await c.recover(code.toLowerCase(), 'new password here'), isNull);
      c.lock();
      expect(await c.unlock('correct horse battery'), isNotNull);
      await Future<void>.delayed(const Duration(seconds: 2));
      expect(await c.unlock('new password here'), isNull);

      final backup = File('${dir.path}/backup.lgkbackup');
      await c.exportBackup(backup);
      await c.deleteForever(c.byId(item.id)!);
      expect(c.allItems, isEmpty);
      expect(await c.restoreBackup(backup, 'wrong'), isNotNull);
      expect(await c.restoreBackup(backup, 'new password here'), isNull);
      expect(c.byId(item.id)!.title, 'Steam');
      expect(await c.readAttachment(c.byId(item.id)!.attachments.single), [1, 2, 3]);
      c.dispose();
    });
  });
}
