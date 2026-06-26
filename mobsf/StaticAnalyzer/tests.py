#!/usr/bin/env python
import json
import logging
import os
import platform
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from mobsf.MobSF.init import api_key

from django.conf import settings
from django.http import HttpResponse
from django.test import Client, TestCase

logger = logging.getLogger(__name__)

RESCAN = False
# Set RESCAN to True if Static Analyzer Code is modified
EXTS = settings.ANDROID_EXTS + settings.IOS_EXTS + settings.WINDOWS_EXTS


def static_analysis_test():
    """Test Static Analyzer."""
    logger.info('Running Static Analyzer Unit test')
    try:
        uploaded = []
        logger.info('Running Upload Test')
        http_client = Client()
        apk_dir = os.path.join(settings.BASE_DIR, 'StaticAnalyzer/test_files/')
        for filename in os.listdir(apk_dir):
            if not filename.endswith(EXTS):
                continue
            if platform.system() == 'Windows' and filename.endswith('.ipa'):
                continue
            fpath = os.path.join(apk_dir, filename)
            with open(fpath, 'rb') as file_pointer:
                response = http_client.post(
                    '/upload/',
                    {'file': file_pointer})
                obj = json.loads(response.content.decode('utf-8'))
                if response.status_code == 200 and obj['status'] == 'success':
                    logger.info('[OK] Upload OK: %s', filename)
                    uploaded.append(obj)
                else:
                    logger.error('Performing Upload: %s', filename)
                    return True
        logger.info('[OK] Completed Upload test')
        logger.info('Running Static Analysis Test')
        for upl in uploaded:
            scan_url = '/{}/{}/'.format(
                upl['analyzer'],
                upl['hash'])
            if RESCAN:
                scan_url = scan_url + '?rescan=1'
            resp = http_client.get(scan_url, follow=True)
            if resp.status_code == 200:
                logger.info('[OK] Static Analysis Complete: %s', scan_url)
            else:
                logger.error('Performing Static Analysis: %s', scan_url)
                return True
        logger.info('[OK] Static Analysis test completed')
        logger.info('Running PDF Generation Test')
        if platform.system() in ['Darwin', 'Linux']:
            pdfs = [
                '/pdf/02e7989c457ab67eb514a8328779f256/',
                '/pdf/82ab8b2193b3cfb1c737e3a786be363a/',
                '/pdf/6c23c2970551be15f32bbab0b5db0c71/',
                '/pdf/52c50ae824e329ba8b5b7a0f523efffe/',
                '/pdf/57bb5be0ea44a755ada4a93885c3825e/',
                '/pdf/8179b557433835827a70510584f3143e/',
                '/pdf/7b0a23bffc80bac05739ea1af898daad/',
            ]
        else:
            pdfs = [
                '/pdf/02e7989c457ab67eb514a8328779f256/',
                '/pdf/82ab8b2193b3cfb1c737e3a786be363a/',
                '/pdf/52c50ae824e329ba8b5b7a0f523efffe/',
                '/pdf/57bb5be0ea44a755ada4a93885c3825e/',
                '/pdf/8179b557433835827a70510584f3143e/',
                '/pdf/7b0a23bffc80bac05739ea1af898daad/',
            ]

        for pdf in pdfs:
            resp = http_client.get(pdf)
            if (resp.status_code == 200
                    and resp.headers['content-type'] == 'application/pdf'):
                logger.info('[OK] PDF Report Generated: %s', pdf)
            else:
                logger.error('Generating PDF: %s', pdf)
                logger.info(resp.content)
                return True
        logger.info('[OK] PDF Generation test completed')

        # Compare apps test
        logger.info('Running App Compare tests')
        first_app = '82ab8b2193b3cfb1c737e3a786be363a'
        second_app = '52c50ae824e329ba8b5b7a0f523efffe'
        url = '/compare/{}/{}/'.format(first_app, second_app)
        resp = http_client.get(url, follow=True)
        assert (resp.status_code == 200)
        if resp.status_code == 200:
            logger.info('[OK] App compare tests passed successfully')
        else:
            logger.error('App compare tests failed')
            logger.info(resp.content)
            return True

        # Scan shared object or dylib from binaries.
        logger.info('Running Library Analysis test')
        md5 = '82ab8b2193b3cfb1c737e3a786be363a'
        lib = 'apktool_out/lib/arm64-v8a/libdivajni.so'
        url = f'/scan_library/{md5}?library={lib}'
        resp = http_client.get(url, follow=True)
        assert (resp.status_code == 200)
        if resp.status_code == 200:
            logger.info('[OK] Library Analysis test passed successfully')
        else:
            logger.error('Library Analysis test failed')
            logger.info(resp.content)
            return True

        # Search by MD5 and text
        if platform.system() in ['Darwin', 'Linux']:
            scan_md5s = ['02e7989c457ab67eb514a8328779f256',
                         '82ab8b2193b3cfb1c737e3a786be363a',
                         '6c23c2970551be15f32bbab0b5db0c71',
                         '52c50ae824e329ba8b5b7a0f523efffe',
                         '57bb5be0ea44a755ada4a93885c3825e',
                         '8179b557433835827a70510584f3143e',
                         '7b0a23bffc80bac05739ea1af898daad']
        else:
            scan_md5s = ['02e7989c457ab67eb514a8328779f256',
                         '82ab8b2193b3cfb1c737e3a786be363a',
                         '52c50ae824e329ba8b5b7a0f523efffe',
                         '57bb5be0ea44a755ada4a93885c3825e',
                         '8179b557433835827a70510584f3143e',
                         '7b0a23bffc80bac05739ea1af898daad']
        # Search by text
        queries = [
            'diva',
            'webview',
        ]
        logger.info('Running Search test')
        for q in scan_md5s + queries:
            url = f'/search?query={q}'
            resp = http_client.get(url, follow=True)
            assert (resp.status_code == 200)
            if resp.status_code == 200:
                logger.info('[OK] Search by query test passed for %s', q)
            else:
                logger.error('Search by query test failed for %s', q)
                logger.info(resp.content)
                return True
        logger.info('[OK] Search by MD5 and text tests completed')

        # Deleting Scan Results
        logger.info('Running Delete Scan Results test')
        for md5 in scan_md5s:
            resp = http_client.post('/delete_scan/', {'md5': md5})
            if resp.status_code == 200:
                dat = json.loads(resp.content.decode('utf-8'))
                if dat['deleted'] == 'yes':
                    logger.info('[OK] Deleted Scan: %s', md5)
                else:
                    logger.error('Deleting Scan: %s', md5)
                    return True
            else:
                logger.error('Deleting Scan: %s', md5)
                return True
        logger.info('Delete Scan Results test completed')
    except Exception:
        logger.exception('Completing Static Analyzer Test')
        return True
    return False


def api_test():
    """View for Handling REST API Test."""
    logger.info('\nRunning REST API Unit test')
    auth = api_key(settings.MOBSF_HOME)
    try:
        uploaded = []
        logger.info('Running Test on Upload API')
        http_client = Client()
        apk_dir = os.path.join(settings.BASE_DIR, 'StaticAnalyzer/test_files/')
        for filename in os.listdir(apk_dir):
            if not filename.endswith(EXTS):
                continue
            if platform.system() == 'Windows' and filename.endswith('.ipa'):
                continue
            fpath = os.path.join(apk_dir, filename)
            if (platform.system() not in ['Darwin', 'Linux']
                    and fpath.endswith('.ipa')):
                continue
            with open(fpath, 'rb') as file_pointer:
                response = http_client.post(
                    '/api/v1/upload',
                    {'file': file_pointer},
                    HTTP_AUTHORIZATION=auth)
                obj = json.loads(response.content.decode('utf-8'))
                if response.status_code == 200 and 'hash' in obj:
                    logger.info('[OK] Upload OK: %s', filename)
                    uploaded.append(obj)
                else:
                    logger.error('Performing Upload %s', filename)
                    return True
        logger.info('[OK] Completed Upload API test')
        logger.info('Running Static Analysis API Test')
        for upl in uploaded:
            resp = http_client.post(
                '/api/v1/scan',
                {'hash': upl['hash']},
                HTTP_AUTHORIZATION=auth)
            if resp.status_code == 200:
                logger.info('[OK] Static Analysis Complete: %s',
                            upl['file_name'])
            else:
                logger.error('Performing Static Analysis: %s',
                             upl['file_name'])
                return True
        logger.info('[OK] Static Analysis API test completed')
        # Scan List API test
        logger.info('Running Scan List API tests')
        resp = http_client.get('/api/v1/scans', HTTP_AUTHORIZATION=auth)
        if resp.status_code == 200:
            logger.info('Scan List API Test 1 success')
        else:
            logger.error('Scan List API Test 1')
            return True
        resp = http_client.get(
            '/api/v1/scans?page=1&page_size=10', HTTP_AUTHORIZATION=auth)
        if resp.status_code == 200:
            logger.info('Scan List API Test 2 success')
        else:
            logger.error('Scan List API Test 2')
            return True
        resp = http_client.get('/api/v1/scans', HTTP_X_MOBSF_API_KEY=auth)
        if resp.status_code == 200:
            logger.info('Scan List API Test with custom http header 1 success')
        else:
            logger.error('Scan List API Test with custom http header 1')
            return True
        resp = http_client.get(
            '/api/v1/scans?page=1&page_size=10', HTTP_X_MOBSF_API_KEY=auth)
        if resp.status_code == 200:
            logger.info('Scan List API Test with custom http header 2 success')
        else:
            logger.error('Scan List API Test with custom http header 2')
            return True
        logger.info('[OK] Scan List API tests completed')
        # Scan logs tests
        logger.info('Running Scan Logs API tests')
        for upl in uploaded:
            resp = http_client.post(
                '/api/v1/scan_logs',
                {'hash': upl['hash']},
                HTTP_AUTHORIZATION=auth)
            if resp.status_code == 200:
                logs = json.loads(resp.content.decode('utf-8'))
                if 'logs' in logs and len(logs['logs']) > 0:
                    logger.info('[OK] Scan Logs API test: %s', upl['hash'])
            else:
                logger.error('Scan Logs API test: %s', upl['hash'])
                return True
        logger.info('[OK] Static Analysis API test completed')
        # Search API Tests
        logger.info('Running Search API tests')
        for term in ['diva', 'webview', '52c50ae824e329ba8b5b7a0f523efffe']:
            resp = http_client.post(
                '/api/v1/search',
                {'query': term},
                HTTP_AUTHORIZATION=auth)
            if resp.status_code == 200:
                logger.info('[OK] Search API test: %s', term)
            else:
                logger.error('Search API test: %s', term)
                return True
        # PDF Tests
        logger.info('Running PDF Generation API Test')
        if platform.system() in ['Darwin', 'Linux']:
            pdfs = [
                {'hash': '02e7989c457ab67eb514a8328779f256'},
                {'hash': '82ab8b2193b3cfb1c737e3a786be363a'},
                {'hash': '6c23c2970551be15f32bbab0b5db0c71'},
                {'hash': '52c50ae824e329ba8b5b7a0f523efffe'},
                {'hash': '57bb5be0ea44a755ada4a93885c3825e'},
                {'hash': '8179b557433835827a70510584f3143e'},
                {'hash': '7b0a23bffc80bac05739ea1af898daad'},
            ]
        else:
            pdfs = [
                {'hash': '02e7989c457ab67eb514a8328779f256'},
                {'hash': '82ab8b2193b3cfb1c737e3a786be363a'},
                {'hash': '52c50ae824e329ba8b5b7a0f523efffe'},
                {'hash': '57bb5be0ea44a755ada4a93885c3825e'},
                {'hash': '8179b557433835827a70510584f3143e'},
                {'hash': '7b0a23bffc80bac05739ea1af898daad'},
            ]
        for pdf in pdfs:
            resp = http_client.post(
                '/api/v1/download_pdf', pdf, HTTP_AUTHORIZATION=auth)
            resp_custom = http_client.post(
                '/api/v1/download_pdf', pdf, HTTP_X_MOBSF_API_KEY=auth)
            assert (resp.status_code == 200)
            assert (resp_custom.status_code == 200)
            if (resp.status_code == 200
                    and resp.headers['content-type'] == 'application/pdf'):
                logger.info('[OK] PDF Report Generated: %s', pdf['hash'])
            else:
                logger.error('Generating PDF: %s', pdf['hash'])
                logger.info(resp.content)
                return True
        logger.info('[OK] PDF Generation API test completed')
        logger.info('Running JSON Report API test')
        # JSON Report
        ctype = 'application/json; charset=utf-8'
        for jsn in pdfs:
            resp = http_client.post(
                '/api/v1/report_json', jsn, HTTP_AUTHORIZATION=auth)
            resp_custom = http_client.post(
                '/api/v1/report_json', jsn, HTTP_X_MOBSF_API_KEY=auth)
            assert (resp.status_code == 200)
            assert (resp_custom.status_code == 200)
            if (resp.status_code == 200
                    and resp.headers['content-type'] == ctype):
                logger.info('[OK] JSON Report Generated: %s', jsn['hash'])
            else:
                logger.error('Generating JSON Response: %s', jsn['hash'])
                return True
        logger.info('[OK] JSON Report API test completed')
        logger.info('Running Scorecard API test')
        # Scorecard Report
        for scr in pdfs:
            if scr['hash'] == '8179b557433835827a70510584f3143e':
                # Windows Scorecard not yet implemented
                continue
            resp = http_client.post(
                '/api/v1/scorecard', scr, HTTP_AUTHORIZATION=auth)
            resp_custom = http_client.post(
                '/api/v1/scorecard', scr, HTTP_X_MOBSF_API_KEY=auth)
            if resp.status_code == 200 and resp_custom.status_code == 200:
                rp = json.loads(resp.content.decode('utf-8'))
                if 'security_score' in rp:
                    logger.info(
                        '[OK] Security Score - %s', rp['security_score'])
                else:
                    logger.error('Security Score Failed - %s', str(rp))
                    return True
            else:
                logger.error('Scorecard API Failed for - %s', scr['hash'])
                return True
        logger.info('[OK] Scorecard API test completed')
        logger.info('Running View Source API test')
        # View Source tests
        files = [{'file': 'jakhar/aseem/diva/MainActivity.java',
                  'type': 'apk',
                  'hash': '82ab8b2193b3cfb1c737e3a786be363a'},
                 {'file': 'opensecurity/webviewignoressl/MainActivity.java',
                  'type': 'studio',
                  'hash': '52c50ae824e329ba8b5b7a0f523efffe'},
                 {'file': 'DamnVulnerableIOSApp/AppDelegate.m',
                  'type': 'ios',
                  'hash': '57bb5be0ea44a755ada4a93885c3825e'}]
        if platform.system() in ['Darwin', 'Linux']:
            files.append({
                'file': 'helloworld.app/Info.plist',
                'type': 'ipa',
                'hash': '6c23c2970551be15f32bbab0b5db0c71'})
        for sfile in files:
            resp = http_client.post(
                '/api/v1/view_source', sfile, HTTP_AUTHORIZATION=auth)
            resp_custom = http_client.post(
                '/api/v1/view_source', sfile, HTTP_X_MOBSF_API_KEY=auth)
            assert (resp.status_code == 200)
            assert (resp_custom.status_code == 200)
            if resp.status_code == 200:
                dat = json.loads(resp.content.decode('utf-8'))
                if dat['title']:
                    logger.info('[OK] Reading - %s', sfile['file'])
                else:
                    logger.error('Reading - %s', sfile['file'])
                    return True
            else:
                logger.error('Reading - %s', sfile['file'])
                return True
        logger.info('[OK] View Source API test completed')
        # Compare apps test
        logger.info('Running App Compare API tests')
        resp = http_client.post(
            '/api/v1/compare',
            {
                'hash1': '82ab8b2193b3cfb1c737e3a786be363a',
                'hash2': '52c50ae824e329ba8b5b7a0f523efffe',
            },
            HTTP_AUTHORIZATION=auth)
        assert (resp.status_code == 200)
        resp_custom = http_client.post(
            '/api/v1/compare',
            {
                'hash1': '82ab8b2193b3cfb1c737e3a786be363a',
                'hash2': '52c50ae824e329ba8b5b7a0f523efffe',
            },
            HTTP_X_MOBSF_API_KEY=auth)
        assert (resp_custom.status_code == 200)
        if resp.status_code == 200:
            logger.info('[OK] App compare API tests completed')
        else:
            logger.error('App compare API tests failed')
            logger.info(resp.content)
            return True
        logger.info('Running Delete Scan Results test')
        # Suppression tests
        # Android Manifest by rule
        and_hash = '82ab8b2193b3cfb1c737e3a786be363a'
        rule = 'app_is_debuggable'
        typ = 'manifest'
        logger.info('Running Suppression disable by rule for APK manifest')
        resp = http_client.post(
            '/api/v1/suppress_by_rule',
            {
                'hash': and_hash,
                'type': typ,
                'rule': rule,
            },
            HTTP_AUTHORIZATION=auth)
        assert (resp.status_code == 200)
        dat = json.loads(resp.content.decode('utf-8'))
        if dat['status'] == 'ok':
            logger.info('[OK] Suppression by rule - %s', rule)
        else:
            logger.error('[ERROR] Suppression by rule - %s', rule)
            return True
        resp = http_client.post(
            '/api/v1/list_suppressions',
            {
                'hash': and_hash,
            },
            HTTP_AUTHORIZATION=auth)
        assert (resp.status_code == 200)
        dat = resp.content.decode('utf-8')
        if rule in dat:
            logger.info('[OK] Listing suppression for - %s', and_hash)
        else:
            logger.error('[ERROR] Listing suppression for  - %s', and_hash)
            return True
        resp = http_client.post(
            '/api/v1/delete_suppression',
            {
                'hash': and_hash,
                'type': typ,
                'rule': rule,
                'kind': 'rule',
            },
            HTTP_AUTHORIZATION=auth)
        assert (resp.status_code == 200)
        resp = http_client.post(
            '/api/v1/list_suppressions',
            {
                'hash': and_hash,
            },
            HTTP_AUTHORIZATION=auth)
        assert (resp.status_code == 200)
        dat = resp.content.decode('utf-8')
        if rule not in dat:
            logger.info('[OK] Suppression deleted - %s', and_hash)
        else:
            logger.error('[ERROR] Suppression deletion - %s', and_hash)
            return True
        # iOS Code by Files
        ios_hash = '57bb5be0ea44a755ada4a93885c3825e'
        rule = 'ios_app_logging'
        typ = 'code'
        sfile = ('DamnVulnerableIOSApp/Cocoa'
                 'Lumberjack/DDAbstractDatabaseLogger.m')
        logger.info('Running Suppression by files for iOS ObjC source')
        resp = http_client.post(
            '/api/v1/suppress_by_files',
            {
                'hash': ios_hash,
                'type': typ,
                'rule': rule,
            },
            HTTP_AUTHORIZATION=auth)
        assert (resp.status_code == 200)
        dat = json.loads(resp.content.decode('utf-8'))
        if dat['status'] == 'ok':
            logger.info('[OK] Suppression by files for - %s', rule)
        else:
            logger.error('[ERROR] Suppression by files for - %s', rule)
            return True
        resp = http_client.post(
            '/api/v1/list_suppressions',
            {
                'hash': ios_hash,
            },
            HTTP_AUTHORIZATION=auth)
        assert (resp.status_code == 200)
        dat = resp.content.decode('utf-8')
        if rule in dat and sfile in dat:
            logger.info('[OK] Listing suppression for - %s', ios_hash)
        else:
            logger.error('[ERROR] Listing suppression for  - %s', ios_hash)
            return True
        resp = http_client.post(
            '/api/v1/delete_suppression',
            {
                'hash': ios_hash,
                'type': typ,
                'rule': rule,
                'kind': 'file',
            },
            HTTP_AUTHORIZATION=auth)
        assert (resp.status_code == 200)
        resp = http_client.post(
            '/api/v1/list_suppressions',
            {
                'hash': ios_hash,
            },
            HTTP_AUTHORIZATION=auth)
        assert (resp.status_code == 200)
        dat = resp.content.decode('utf-8')
        if rule not in dat:
            logger.info('[OK] Suppression deleted - %s', ios_hash)
        else:
            logger.error('[ERROR] Suppression deletion - %s', ios_hash)
            return True
        # Deleting Scan Results
        if platform.system() in ['Darwin', 'Linux']:
            scan_md5s = ['02e7989c457ab67eb514a8328779f256',
                         '82ab8b2193b3cfb1c737e3a786be363a',
                         '6c23c2970551be15f32bbab0b5db0c71',
                         '52c50ae824e329ba8b5b7a0f523efffe',
                         '57bb5be0ea44a755ada4a93885c3825e',
                         '8179b557433835827a70510584f3143e',
                         '7b0a23bffc80bac05739ea1af898daad',
                         ]
        else:
            scan_md5s = ['02e7989c457ab67eb514a8328779f256',
                         '82ab8b2193b3cfb1c737e3a786be363a',
                         '52c50ae824e329ba8b5b7a0f523efffe',
                         '57bb5be0ea44a755ada4a93885c3825e',
                         '8179b557433835827a70510584f3143e',
                         '7b0a23bffc80bac05739ea1af898daad',
                         ]
        for md5 in scan_md5s:
            resp = http_client.post(
                '/api/v1/delete_scan', {'hash': md5}, HTTP_AUTHORIZATION=auth)
            if resp.status_code == 200:
                dat = json.loads(resp.content.decode('utf-8'))
                if dat['deleted'] == 'yes':
                    logger.info('[OK] Deleted Scan: %s', md5)
                else:
                    logger.error('Deleting Scan: %s', md5)
                    return True
            else:
                logger.error('Deleting Scan: %s', md5)
                return True
        logger.info('Delete Scan Results API test completed')
    except Exception:
        logger.exception('Completing REST API Unit Test')
        return True
    return False


def start_test(request):
    """Static Analyzer Unit test."""
    item = request.GET.get('module', 'static')
    if item == 'static':
        comp = 'static_analyzer'
        failed_stat = static_analysis_test()
    else:
        comp = 'static_analyzer_api'
        failed_stat = api_test()
    try:
        if failed_stat:
            message = 'some tests failed'
            resp_code = 403
        else:
            message = 'all tests completed'
            resp_code = 200
    except Exception:
        resp_code = 403
        message = 'error'
    logger.info('\n\nALL TESTS COMPLETED!')
    logger.info('Test Status: %s', message)
    return HttpResponse(json.dumps({comp: message}),
                        content_type='application/json; charset=utf-8',
                        status=resp_code)


class StaticAnalyzerAndAPI(TestCase):
    """Unit Tests."""

    def setUp(self):
        self.http_client = Client()

    def test_static_analyzer(self):
        resp = self.http_client.post('/tests/?module=static')
        self.assertEqual(resp.status_code, 200)

    def test_rest_api(self):
        resp = self.http_client.post('/tests/?module=api')
        self.assertEqual(resp.status_code, 200)


class ApkEditorModelAndPathTests(TestCase):
    """APK editor model and path tests."""

    def test_editor_paths_are_under_source_scan_directory(self):
        from mobsf.StaticAnalyzer.views.android.apk_editor.constants import (
            BUILD_DIR,
            EDITOR_DIR,
            LOG_DIR,
            LOG_FILE,
            OUTPUT_DIR,
            WORKSPACE_DIR,
        )
        from mobsf.StaticAnalyzer.views.android.apk_editor.paths import (
            editor_paths,
        )

        source_md5 = '0123456789abcdef0123456789abcdef'
        session_id = 'session-123'

        paths = editor_paths(source_md5, session_id)
        source_dir = Path(settings.UPLD_DIR) / source_md5
        session_root = source_dir / EDITOR_DIR / session_id
        logs = session_root / LOG_DIR

        self.assertEqual(paths.source_md5, source_md5)
        self.assertEqual(paths.session_id, session_id)
        self.assertEqual(paths.source_dir, source_dir)
        self.assertEqual(paths.source_apk, source_dir / f'{source_md5}.apk')
        self.assertEqual(paths.session_root, session_root)
        self.assertEqual(paths.workspace, session_root / WORKSPACE_DIR)
        self.assertEqual(paths.build, session_root / BUILD_DIR)
        self.assertEqual(paths.output, session_root / OUTPUT_DIR)
        self.assertEqual(paths.logs, logs)
        self.assertEqual(paths.log_file, logs / LOG_FILE)

    def test_editor_paths_rejects_path_traversal_session_id(self):
        from mobsf.StaticAnalyzer.views.android.apk_editor.paths import (
            editor_paths,
        )

        source_md5 = '0123456789abcdef0123456789abcdef'

        with self.assertRaises(ValueError):
            editor_paths(source_md5, '../escape')
        with self.assertRaises(ValueError):
            editor_paths(source_md5, 'bad.session')

    def test_editor_paths_rejects_invalid_source_md5(self):
        from mobsf.StaticAnalyzer.views.android.apk_editor.paths import (
            editor_paths,
        )

        with self.assertRaises(ValueError):
            editor_paths('not-a-valid-md5', 'session-123')

    def test_apk_editor_session_defaults(self):
        from mobsf.StaticAnalyzer.views.android.apk_editor.constants import (
            STATE_ACTIVE,
        )
        from mobsf.StaticAnalyzer.models import (
            ApkEditorSession,
            RecentScansDB,
        )

        source_md5 = 'fedcba9876543210fedcba9876543210'
        RecentScansDB.objects.create(MD5=source_md5)

        session = ApkEditorSession.objects.create(
            source_md5=source_md5,
            session_id='session-defaults',
        )

        self.assertEqual(session.state, STATE_ACTIVE)
        self.assertFalse(session.dirty)
        self.assertEqual(session.operation_metadata, {})
        self.assertEqual(session.last_error, '')


class ApkEditorWorkspaceTests(TestCase):
    """APK editor workspace and command tests."""

    def test_redact_text_hides_secret_values(self):
        from mobsf.StaticAnalyzer.views.android.apk_editor.command import (
            redact_text,
        )

        text = (
            'store_password=abc123 key_password=def456 '
            'api_key=secret authorization=bearer'
        )

        redacted = redact_text(text)

        self.assertNotIn('abc123', redacted)
        self.assertNotIn('def456', redacted)
        self.assertNotIn('secret', redacted)
        self.assertNotIn('bearer', redacted)
        self.assertIn('store_password=<redacted>', redacted)
        self.assertIn('key_password=<redacted>', redacted)
        self.assertIn('api_key=<redacted>', redacted)
        self.assertIn('authorization=<redacted>', redacted)

    def test_redact_text_hides_quoted_secret_values(self):
        from mobsf.StaticAnalyzer.views.android.apk_editor.command import (
            redact_text,
        )

        text = (
            'password="abc 123" authorization="Bearer abc" '
            "token='abc def' api_key=secret"
        )

        redacted = redact_text(text)

        self.assertNotIn('abc', redacted)
        self.assertNotIn('123', redacted)
        self.assertNotIn('Bearer', redacted)
        self.assertNotIn('def', redacted)
        self.assertNotIn('secret', redacted)
        self.assertIn('password=<redacted>', redacted)
        self.assertIn('authorization=<redacted>', redacted)
        self.assertIn('token=<redacted>', redacted)
        self.assertIn('api_key=<redacted>', redacted)

    def test_create_workspace_dirs_creates_expected_directories(self):
        from mobsf.StaticAnalyzer.views.android.apk_editor.paths import (
            editor_paths,
        )
        from mobsf.StaticAnalyzer.views.android.apk_editor.workspace import (
            create_workspace_dirs,
        )

        with tempfile.TemporaryDirectory() as upload_dir:
            with self.settings(UPLD_DIR=upload_dir):
                paths = editor_paths(
                    'c' * 32,
                    '20260626-120002-cccc',
                )

                create_workspace_dirs(paths)

                self.assertTrue(paths.workspace.is_dir())
                self.assertTrue(paths.build.is_dir())
                self.assertTrue(paths.output.is_dir())
                self.assertTrue(paths.logs.is_dir())

    def test_remove_build_workspace_deletes_workspace_and_build(self):
        from mobsf.StaticAnalyzer.views.android.apk_editor.paths import (
            editor_paths,
        )
        from mobsf.StaticAnalyzer.views.android.apk_editor.workspace import (
            create_workspace_dirs,
            remove_build_workspace,
        )

        with tempfile.TemporaryDirectory() as upload_dir:
            with self.settings(UPLD_DIR=upload_dir):
                paths = editor_paths(
                    'c' * 32,
                    '20260626-120002-cccc',
                )
                create_workspace_dirs(paths)

                remove_build_workspace(paths)

                self.assertFalse(paths.workspace.exists())
                self.assertFalse(paths.build.exists())
                self.assertTrue(paths.output.is_dir())
                self.assertTrue(paths.logs.is_dir())

    def test_run_logged_command_writes_command_output(self):
        from mobsf.StaticAnalyzer.views.android.apk_editor.command import (
            run_logged_command,
        )
        from mobsf.StaticAnalyzer.views.android.apk_editor.paths import (
            editor_paths,
        )

        completed = Mock(returncode=0, stdout='ok', stderr='')
        with tempfile.TemporaryDirectory() as upload_dir:
            with self.settings(UPLD_DIR=upload_dir):
                paths = editor_paths(
                    'c' * 32,
                    '20260626-120002-cccc',
                )
                paths.session_root.mkdir(parents=True)

                with patch('subprocess.run', return_value=completed):
                    result = run_logged_command(
                        ['echo', 'ok'],
                        paths.log_file,
                        cwd=paths.session_root,
                    )

                self.assertEqual(result.returncode, 0)
                log_text = paths.log_file.read_text('utf-8')
                self.assertIn('$ echo ok', log_text)
                self.assertIn('ok', log_text)

    def test_run_logged_command_accepts_path_arguments(self):
        from mobsf.StaticAnalyzer.views.android.apk_editor.command import (
            run_logged_command,
        )
        from mobsf.StaticAnalyzer.views.android.apk_editor.paths import (
            editor_paths,
        )

        completed = Mock(returncode=0, stdout='', stderr='')
        with tempfile.TemporaryDirectory() as upload_dir:
            with self.settings(UPLD_DIR=upload_dir):
                paths = editor_paths(
                    'c' * 32,
                    '20260626-120002-cccc',
                )
                paths.session_root.mkdir(parents=True)
                path_arg = Path('AndroidManifest.xml')

                with patch('subprocess.run', return_value=completed) as run:
                    run_logged_command(
                        ['cat', path_arg],
                        paths.log_file,
                        cwd=paths.session_root,
                    )

                run_args = run.call_args.args[0]
                self.assertTrue(all(isinstance(arg, str) for arg in run_args))
                log_text = paths.log_file.read_text('utf-8')
                self.assertIn('$ cat AndroidManifest.xml', log_text)
