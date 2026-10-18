import 'dart:convert';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

const backupFile = 'money_backup.json';

abstract class CloudProvider {
  Future<void> upload(String content);
  Future<String?> download();
}

void _check(http.Response r, String who) {
  if (r.statusCode >= 300) {
    throw Exception('$who: ${r.statusCode} ${r.body}');
  }
}

/// WebDAV قياسي (Basic Auth)
class WebDavProvider implements CloudProvider {
  final String folderUrl, user, pass;
  WebDavProvider(this.folderUrl, this.user, this.pass);

  String get base => folderUrl.endsWith('/') ? folderUrl : '$folderUrl/';
  Map<String, String> get headers =>
      {'Authorization': 'Basic ${base64Encode(utf8.encode('$user:$pass'))}'};

  Future<void> ensureFolder() async {
    final req = http.Request('MKCOL', Uri.parse(base));
    req.headers.addAll(headers);
    await req.send(); // 405 = موجود مسبقاً، نتجاهل النتيجة
  }

  @override
  Future<void> upload(String content) async {
    await ensureFolder();
    final r = await http.put(Uri.parse('$base$backupFile'),
        headers: {...headers, 'Content-Type': 'application/json'},
        body: utf8.encode(content));
    _check(r, 'WebDAV');
  }

  @override
  Future<String?> download() async {
    final r = await http.get(Uri.parse('$base$backupFile'), headers: headers);
    if (r.statusCode == 404) return null;
    _check(r, 'WebDAV');
    return utf8.decode(r.bodyBytes);
  }
}

/// Nextcloud عبر WebDAV: server/remote.php/dav/files/USER/MoneyManager
class NextcloudProvider extends WebDavProvider {
  NextcloudProvider(String server, String user, String pass)
      : super(
            '${server.replaceAll(RegExp(r'/+$'), '')}/remote.php/dav/files/${Uri.encodeComponent(user)}/MoneyManager',
            user,
            pass);
}

/// Dropbox: OAuth 2.0 PKCE بدون redirect (المستخدم ينسخ الرمز ويلصقه)
class DropboxProvider implements CloudProvider {
  final String appKey, refreshToken;
  DropboxProvider(this.appKey, this.refreshToken);

  static String _verifier = '';

  static Uri startAuth(String appKey) {
    final rnd = Random.secure();
    _verifier = base64UrlEncode(List<int>.generate(48, (_) => rnd.nextInt(256)))
        .replaceAll('=', '');
    final challenge = base64UrlEncode(sha256.convert(utf8.encode(_verifier)).bytes)
        .replaceAll('=', '');
    return Uri.https('www.dropbox.com', '/oauth2/authorize', {
      'client_id': appKey,
      'response_type': 'code',
      'code_challenge': challenge,
      'code_challenge_method': 'S256',
      'token_access_type': 'offline',
    });
  }

  static Future<String> finishAuth(String appKey, String code) async {
    final r = await http.post(Uri.parse('https://api.dropboxapi.com/oauth2/token'),
        body: {
          'code': code.trim(),
          'grant_type': 'authorization_code',
          'code_verifier': _verifier,
          'client_id': appKey,
        });
    _check(r, 'Dropbox');
    return jsonDecode(r.body)['refresh_token'] as String;
  }

  Future<String> _token() async {
    final r = await http.post(Uri.parse('https://api.dropboxapi.com/oauth2/token'),
        body: {
          'grant_type': 'refresh_token',
          'refresh_token': refreshToken,
          'client_id': appKey,
        });
    _check(r, 'Dropbox');
    return jsonDecode(r.body)['access_token'] as String;
  }

  @override
  Future<void> upload(String content) async {
    final t = await _token();
    final r = await http.post(
        Uri.parse('https://content.dropboxapi.com/2/files/upload'),
        headers: {
          'Authorization': 'Bearer $t',
          'Dropbox-API-Arg': jsonEncode({'path': '/$backupFile', 'mode': 'overwrite'}),
          'Content-Type': 'application/octet-stream',
        },
        body: utf8.encode(content));
    _check(r, 'Dropbox');
  }

  @override
  Future<String?> download() async {
    final t = await _token();
    final r = await http.post(
        Uri.parse('https://content.dropboxapi.com/2/files/download'),
        headers: {
          'Authorization': 'Bearer $t',
          'Dropbox-API-Arg': jsonEncode({'path': '/$backupFile'}),
        });
    if (r.statusCode == 409) return null;
    _check(r, 'Dropbox');
    return utf8.decode(r.bodyBytes);
  }
}

/// OneDrive عبر Microsoft Graph (Device Code Flow - بدون redirect)
class OneDriveProvider implements CloudProvider {
  final String clientId, refreshToken;
  OneDriveProvider(this.clientId, this.refreshToken);

  static const _auth = 'https://login.microsoftonline.com/consumers/oauth2/v2.0';
  static const _scope = 'Files.ReadWrite.AppFolder offline_access';
  static const _file =
      'https://graph.microsoft.com/v1.0/me/drive/special/approot:/$backupFile:/content';

  static Future<Map<String, dynamic>> startDevice(String clientId) async {
    final r = await http.post(Uri.parse('$_auth/devicecode'),
        body: {'client_id': clientId, 'scope': _scope});
    _check(r, 'OneDrive');
    return jsonDecode(r.body) as Map<String, dynamic>;
  }

  static Future<String> pollDevice(String clientId, Map<String, dynamic> d) async {
    final interval = (d['interval'] as num?)?.toInt() ?? 5;
    final expires = (d['expires_in'] as num?)?.toInt() ?? 900;
    final deadline = DateTime.now().add(Duration(seconds: expires));
    while (DateTime.now().isBefore(deadline)) {
      await Future.delayed(Duration(seconds: interval));
      final r = await http.post(Uri.parse('$_auth/token'), body: {
        'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
        'client_id': clientId,
        'device_code': d['device_code'],
      });
      final j = jsonDecode(r.body) as Map<String, dynamic>;
      if (j['refresh_token'] != null) return j['refresh_token'] as String;
      final e = j['error'];
      if (e != 'authorization_pending' && e != 'slow_down') {
        throw Exception(j['error_description'] ?? e);
      }
    }
    throw Exception('انتهت مهلة الربط');
  }

  Future<String> _token() async {
    final r = await http.post(Uri.parse('$_auth/token'), body: {
      'grant_type': 'refresh_token',
      'refresh_token': refreshToken,
      'client_id': clientId,
      'scope': _scope,
    });
    _check(r, 'OneDrive');
    final j = jsonDecode(r.body) as Map<String, dynamic>;
    if (j['refresh_token'] != null) {
      final p = await SharedPreferences.getInstance();
      await p.setString('od_refresh', j['refresh_token'] as String);
    }
    return j['access_token'] as String;
  }

  @override
  Future<void> upload(String content) async {
    final t = await _token();
    final r = await http.put(Uri.parse(_file),
        headers: {'Authorization': 'Bearer $t', 'Content-Type': 'application/json'},
        body: utf8.encode(content));
    _check(r, 'OneDrive');
  }

  @override
  Future<String?> download() async {
    final t = await _token();
    final req = http.Request('GET', Uri.parse(_file))
      ..followRedirects = false
      ..headers['Authorization'] = 'Bearer $t';
    final res = await http.Response.fromStream(await req.send());
    if (res.statusCode == 404) return null;
    if (res.statusCode >= 300 && res.statusCode < 400) {
      final loc = res.headers['location'];
      if (loc == null) throw Exception('OneDrive: redirect');
      final r2 = await http.get(Uri.parse(loc));
      _check(r2, 'OneDrive');
      return utf8.decode(r2.bodyBytes);
    }
    _check(res, 'OneDrive');
    return utf8.decode(res.bodyBytes);
  }
}
