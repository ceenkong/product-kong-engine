#!/usr/bin/env python
import json
import logging
import os
import platform
import shutil
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from mobsf.MobSF.init import api_key

from django.conf import settings
from django.contrib.auth import get_user_model
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


class ApkEditorEndpointTests(TestCase):
    """APK editor JSON endpoint tests."""

    def setUp(self):
        self.auth = api_key(settings.MOBSF_HOME)
        self.http_client = Client()

    def _session_json(self, source_md5='a' * 32, session_id='session-123'):
        return {
            'status': 'ok',
            'hash': source_md5,
            'session_id': session_id,
            'state': 'active',
            'dirty': False,
            'output_apk': '',
            'last_error': '',
            'operation_metadata': {},
        }

    def _login_superuser(self, client=None):
        client = client or self.http_client
        user = get_user_model().objects.create_superuser(
            username='apk-editor-admin',
            email='apk-editor-admin@example.com',
            password='password',
        )
        client.force_login(user)

    def _login_regular_user(self, client=None):
        client = client or self.http_client
        user = get_user_model().objects.create_user(
            username='apk-editor-user',
            email='apk-editor-user@example.com',
            password='password',
        )
        client.force_login(user)

    @patch('mobsf.StaticAnalyzer.views.android.apk_editor.api.start_session')
    def test_api_start_requires_hash(self, start_session_mock):
        resp = self.http_client.post(
            '/api/v1/apk_editor/start',
            HTTP_AUTHORIZATION=self.auth,
        )

        self.assertEqual(resp.status_code, 422)
        self.assertEqual(json.loads(resp.content), {'error': 'Missing hash'})
        start_session_mock.assert_not_called()

    @patch('mobsf.StaticAnalyzer.views.android.apk_editor.api.start_session')
    def test_api_start_returns_session_json(self, start_session_mock):
        source_md5 = 'b' * 32
        start_session_mock.return_value = self._session_json(source_md5)

        resp = self.http_client.post(
            '/api/v1/apk_editor/start',
            {'hash': source_md5},
            HTTP_AUTHORIZATION=self.auth,
        )

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(json.loads(resp.content)['session_id'], 'session-123')
        start_session_mock.assert_called_once_with(source_md5)

    @patch('mobsf.StaticAnalyzer.views.android.apk_editor.api.start_session')
    def test_api_start_hides_unexpected_service_error(self, start_session_mock):
        start_session_mock.side_effect = RuntimeError('/secret/path')

        resp = self.http_client.post(
            '/api/v1/apk_editor/start',
            {'hash': 'a' * 32},
            HTTP_AUTHORIZATION=self.auth,
        )

        response_text = resp.content.decode('utf-8')
        self.assertEqual(resp.status_code, 500)
        self.assertNotIn('/secret/path', response_text)
        self.assertEqual(
            json.loads(response_text),
            {'error': 'APK editor operation failed'},
        )

    @patch('mobsf.StaticAnalyzer.views.android.apk_editor.web.start_session')
    def test_web_start_returns_session_json(self, start_session_mock):
        self._login_superuser()
        source_md5 = 'c' * 32
        start_session_mock.return_value = self._session_json(source_md5)

        resp = self.http_client.post(
            '/apk_editor/start/',
            {'hash': source_md5},
        )

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(json.loads(resp.content)['session_id'], 'session-123')
        start_session_mock.assert_called_once_with(source_md5)

    def test_web_editor_home_renders_standalone_upload_page(self):
        self._login_superuser()

        resp = self.http_client.get('/apk_editor/')
        html = resp.content.decode('utf-8')

        self.assertEqual(resp.status_code, 200)
        self.assertIn('APK Editor', html)
        self.assertIn('id="apk-editor-upload"', html)
        self.assertIn('data-upload-url="/apk_editor/upload/"', html)
        self.assertIn('id="apk-editor-upload-progress"', html)
        self.assertIn('id="apk-editor-upload-progress-bar"', html)
        self.assertIn('id="apk-editor-upload-progress-text"', html)
        self.assertIn('id="apk-editor"', html)
        self.assertIn('others/js/apk_editor.js', html)

    def test_apk_editor_upload_script_tracks_upload_progress(self):
        script_path = (
            Path(settings.BASE_DIR)
            / 'static'
            / 'others'
            / 'js'
            / 'apk_editor.js'
        )
        script = script_path.read_text(encoding='utf-8')

        self.assertIn('new XMLHttpRequest()', script)
        self.assertIn('.upload.onprogress', script)
        self.assertIn('setUploadProgress', script)

    def test_nav_contains_global_apk_editor_link(self):
        self._login_superuser()

        resp = self.http_client.get('/apk_editor/')
        html = resp.content.decode('utf-8')

        self.assertEqual(resp.status_code, 200)
        self.assertIn('href="/apk_editor/"', html)
        self.assertIn('APK Editor', html)

    @patch('mobsf.StaticAnalyzer.views.android.apk_editor.session.decompile_apk')
    def test_web_upload_apk_creates_editor_session_without_scan(
            self,
            decompile_mock):
        from hashlib import md5
        from django.core.files.uploadedfile import SimpleUploadedFile
        from mobsf.StaticAnalyzer.models import RecentScansDB

        self._login_superuser()
        content = b'PK\x03\x04apk editor standalone upload'
        source_md5 = md5(content).hexdigest()
        upload = SimpleUploadedFile(
            'standalone.apk',
            content,
            content_type='application/vnd.android.package-archive',
        )

        with tempfile.TemporaryDirectory() as upload_dir:
            with self.settings(UPLD_DIR=upload_dir):
                resp = self.http_client.post(
                    '/apk_editor/upload/',
                    {'file': upload},
                )
                payload = json.loads(resp.content)
                source_path = Path(upload_dir) / source_md5 / f'{source_md5}.apk'

                self.assertTrue(source_path.is_file())

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(payload['status'], 'ok')
        self.assertEqual(payload['hash'], source_md5)
        self.assertTrue(payload['session_id'])
        self.assertEqual(RecentScansDB.objects.count(), 0)
        decompile_mock.assert_called_once()

    @patch('mobsf.StaticAnalyzer.views.android.apk_editor.web.start_session')
    def test_web_start_requires_scan_permission(self, start_session_mock):
        self._login_regular_user()

        with self.settings(DISABLE_AUTHENTICATION='0'):
            resp = self.http_client.post(
                '/apk_editor/start/',
                {'hash': 'c' * 32},
            )

        self.assertEqual(resp.status_code, 403)
        self.assertTrue(
            resp['Content-Type'].startswith('application/json'),
            resp['Content-Type'],
        )
        self.assertEqual(
            json.loads(resp.content),
            {'status': 'failed', 'error': 'Permission denied'},
        )
        start_session_mock.assert_not_called()

    @patch('mobsf.StaticAnalyzer.views.android.apk_editor.web.start_session')
    def test_web_start_requires_csrf_token(self, start_session_mock):
        csrf_client = Client(enforce_csrf_checks=True)
        self._login_superuser(client=csrf_client)
        source_md5 = 'c' * 32
        start_session_mock.return_value = self._session_json(source_md5)

        resp = csrf_client.post(
            '/apk_editor/start/',
            {'hash': source_md5},
        )

        self.assertEqual(resp.status_code, 403)
        start_session_mock.assert_not_called()

    @patch(
        'mobsf.StaticAnalyzer.views.android.apk_editor.web.get_editor_status')
    def test_web_status_respects_disabled_authentication(
            self,
            get_status_mock):
        source_md5 = 'g' * 32
        get_status_mock.return_value = self._session_json(
            source_md5,
            session_id='disabled-auth',
        )

        with self.settings(DISABLE_AUTHENTICATION='1'):
            resp = self.http_client.get(
                '/apk_editor/status/',
                {'hash': source_md5},
            )

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(
            json.loads(resp.content)['session_id'],
            'disabled-auth',
        )
        get_status_mock.assert_called_once_with(source_md5, None)

    @patch(
        'mobsf.StaticAnalyzer.views.android.apk_editor.api.get_editor_status')
    def test_api_status_returns_session_json(self, get_status_mock):
        source_md5 = 'd' * 32
        get_status_mock.return_value = self._session_json(
            source_md5,
            session_id='status-session',
        )

        resp = self.http_client.get(
            '/api/v1/apk_editor/status',
            {'hash': source_md5, 'session_id': 'status-session'},
            HTTP_AUTHORIZATION=self.auth,
        )

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(
            json.loads(resp.content)['session_id'],
            'status-session',
        )
        get_status_mock.assert_called_once_with(source_md5, 'status-session')

    @patch('mobsf.StaticAnalyzer.views.android.apk_editor.web.discard_session')
    def test_web_discard_requires_session_id(self, discard_session_mock):
        self._login_superuser()

        resp = self.http_client.post(
            '/apk_editor/discard/',
            {'hash': 'e' * 32},
        )

        self.assertEqual(resp.status_code, 422)
        self.assertEqual(json.loads(resp.content)['status'], 'failed')
        discard_session_mock.assert_not_called()

    @patch('mobsf.StaticAnalyzer.views.android.apk_editor.api.discard_session')
    def test_api_discard_returns_session_json(self, discard_session_mock):
        source_md5 = 'f' * 32
        discard_session_mock.return_value = self._session_json(
            source_md5,
            session_id='discard-session',
        )

        resp = self.http_client.post(
            '/api/v1/apk_editor/discard',
            {'hash': source_md5, 'session_id': 'discard-session'},
            HTTP_AUTHORIZATION=self.auth,
        )

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(
            json.loads(resp.content)['session_id'],
            'discard-session',
        )
        discard_session_mock.assert_called_once_with(
            source_md5,
            'discard-session',
        )

    @patch(
        'mobsf.StaticAnalyzer.views.android.apk_editor.api.inject_frida_gadget')
    def test_api_frida_gadget_returns_operation_json(self, inject_mock):
        source_md5 = '1' * 32
        inject_mock.return_value = {
            'status': 'ok',
            'frida_gadget_injected': True,
            'abis': ['arm64-v8a'],
        }

        resp = self.http_client.post(
            '/api/v1/apk_editor/frida_gadget',
            {
                'hash': source_md5,
                'session_id': 'frida-session',
                'abis': ['arm64-v8a'],
            },
            HTTP_AUTHORIZATION=self.auth,
        )

        self.assertEqual(resp.status_code, 200)
        self.assertTrue(json.loads(resp.content)['frida_gadget_injected'])
        inject_mock.assert_called_once_with(
            source_md5,
            'frida-session',
            ['arm64-v8a'],
        )

    @patch(
        'mobsf.StaticAnalyzer.views.android.apk_editor.web.inject_frida_gadget')
    def test_web_frida_gadget_requires_session_id(self, inject_mock):
        self._login_superuser()

        resp = self.http_client.post(
            '/apk_editor/frida_gadget/',
            {'hash': '1' * 32},
        )

        self.assertEqual(resp.status_code, 422)
        self.assertEqual(json.loads(resp.content)['status'], 'failed')
        inject_mock.assert_not_called()

    @patch('mobsf.StaticAnalyzer.views.android.apk_editor.api.obfuscate_session')
    def test_api_obfuscate_returns_operation_json(self, obfuscate_mock):
        source_md5 = '4' * 32
        obfuscate_mock.return_value = {
            'status': 'ok',
            'mapping': '/tmp/obfuscation.json',
            'summary': {'assets': {}},
        }

        resp = self.http_client.post(
            '/api/v1/apk_editor/obfuscate',
            {
                'hash': source_md5,
                'session_id': 'obf-session',
                'assets': '1',
                'anti_analysis': '1',
            },
            HTTP_AUTHORIZATION=self.auth,
        )

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(json.loads(resp.content)['status'], 'ok')
        obfuscate_mock.assert_called_once_with(
            source_md5,
            'obf-session',
            {
                'smali': False,
                'assets': True,
                'resources': False,
                'anti_analysis': True,
                'frida_hide': False,
            },
        )

    @patch('mobsf.StaticAnalyzer.views.android.apk_editor.web.obfuscate_session')
    def test_web_obfuscate_requires_session_id(self, obfuscate_mock):
        self._login_superuser()

        resp = self.http_client.post(
            '/apk_editor/obfuscate/',
            {'hash': '4' * 32},
        )

        self.assertEqual(resp.status_code, 422)
        self.assertEqual(json.loads(resp.content)['status'], 'failed')
        obfuscate_mock.assert_not_called()

    @patch('mobsf.StaticAnalyzer.views.android.apk_editor.api.save_session')
    def test_api_save_returns_session_json(self, save_mock):
        source_md5 = '7' * 32
        save_mock.return_value = self._session_json(
            source_md5,
            session_id='save-session',
        )

        resp = self.http_client.post(
            '/api/v1/apk_editor/save',
            {
                'hash': source_md5,
                'session_id': 'save-session',
                'signing': 'debug',
            },
            HTTP_AUTHORIZATION=self.auth,
        )

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(json.loads(resp.content)['session_id'], 'save-session')
        save_mock.assert_called_once_with(
            source_md5,
            'save-session',
            {'signing': 'debug'},
        )

    def test_web_download_returns_saved_apk(self):
        from mobsf.StaticAnalyzer.models import ApkEditorSession
        from mobsf.StaticAnalyzer.views.android.apk_editor.constants import (
            STATE_SAVED,
        )
        from mobsf.StaticAnalyzer.views.android.apk_editor.paths import (
            editor_paths,
        )

        self._login_superuser()
        source_md5 = '8' * 32
        paths = editor_paths(source_md5, 'download-session')
        shutil.rmtree(paths.session_root, ignore_errors=True)
        self.addCleanup(
            shutil.rmtree,
            paths.session_root,
            ignore_errors=True,
        )
        paths.output.mkdir(parents=True)
        output_apk = paths.output / f'{source_md5}-edited.apk'
        output_apk.write_bytes(b'edited-apk')
        ApkEditorSession.objects.create(
            source_md5=source_md5,
            session_id='download-session',
            state=STATE_SAVED,
            dirty=True,
            output_apk=str(output_apk),
        )

        resp = self.http_client.get(
            '/apk_editor/download/',
            {'hash': source_md5, 'session_id': 'download-session'},
        )

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content, b'edited-apk')


class ApkEditorTemplateTests(TestCase):
    """APK editor template tests."""

    def _render_android_binary_report(self, app_type='apk'):
        from django.template.loader import render_to_string
        from django.utils import translation

        with translation.override('zh-hans'):
            return render_to_string(
                'static_analysis/android_binary_analysis.html',
                {
                    'md5': 'a' * 32,
                    'app_type': app_type,
                    'title': 'Android Binary Analysis',
                    'version': 'test',
                    'exported_count': {},
                    'activities': [],
                    'services': [],
                    'receivers': [],
                    'providers': [],
                },
            )

    def test_android_binary_template_does_not_contain_editor_mount(self):
        html = self._render_android_binary_report()

        self.assertNotIn('id="apk-editor"', html)
        self.assertNotIn('data-start-url="/apk_editor/start/"', html)
        self.assertNotIn('others/js/apk_editor.js', html)

    def test_android_binary_template_hides_editor_for_non_apk(self):
        html = self._render_android_binary_report(app_type='so')

        self.assertNotIn('id="apk-editor"', html)
        self.assertNotIn('others/js/apk_editor.js', html)


class ApkEditorFridaTests(TestCase):
    """APK editor Frida Gadget tests."""

    def _fresh_paths(self, source_md5, session_id):
        from mobsf.StaticAnalyzer.views.android.apk_editor.paths import (
            editor_paths,
        )

        paths = editor_paths(source_md5, session_id)
        shutil.rmtree(paths.session_root, ignore_errors=True)
        self.addCleanup(
            shutil.rmtree,
            paths.session_root,
            ignore_errors=True,
        )
        return paths

    def test_detect_abis_returns_existing_lib_dirs(self):
        from mobsf.StaticAnalyzer.views.android.apk_editor.frida import (
            detect_abis,
        )

        paths = self._fresh_paths('2' * 32, 'frida-abis')
        (paths.workspace / 'lib/arm64-v8a').mkdir(parents=True)
        (paths.workspace / 'lib/armeabi-v7a').mkdir(parents=True)

        self.assertEqual(detect_abis(paths), ['arm64-v8a', 'armeabi-v7a'])

    @patch('mobsf.StaticAnalyzer.views.android.apk_editor.frida.ensure_gadget')
    def test_inject_frida_gadget_marks_session_dirty(self, ensure_gadget_mock):
        from mobsf.StaticAnalyzer.models import ApkEditorSession
        from mobsf.StaticAnalyzer.views.android.apk_editor.frida import (
            inject_frida_gadget,
        )

        source_md5 = '3' * 32
        session = ApkEditorSession.objects.create(
            source_md5=source_md5,
            session_id='frida-session',
        )
        paths = self._fresh_paths(source_md5, session.session_id)
        (paths.workspace / 'smali/com/example').mkdir(parents=True)
        (paths.workspace / 'AndroidManifest.xml').write_text(
            '<manifest package="com.example">'
            '<application android:name=".App"/>'
            '</manifest>',
            encoding='utf-8',
        )
        app_smali = paths.workspace / 'smali/com/example/App.smali'
        app_smali.write_text(
            '.class public Lcom/example/App;\n'
            '.super Landroid/app/Application;\n'
            '.method public onCreate()V\n'
            '    .locals 0\n'
            '    return-void\n'
            '.end method\n',
            encoding='utf-8',
        )
        ensure_gadget_mock.return_value = (
            paths.workspace / 'lib/arm64-v8a/libfrida-gadget.so'
        )

        result = inject_frida_gadget(
            source_md5,
            session.session_id,
            ['arm64-v8a'],
        )

        session.refresh_from_db()
        self.assertTrue(session.dirty)
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['frida_gadget_injected'], True)
        self.assertIn('loadLibrary', app_smali.read_text(encoding='utf-8'))

    @patch('mobsf.StaticAnalyzer.views.android.apk_editor.frida.ensure_gadget')
    def test_inject_frida_gadget_creates_application_when_missing(
            self,
            ensure_gadget_mock):
        from mobsf.StaticAnalyzer.models import ApkEditorSession
        from mobsf.StaticAnalyzer.views.android.apk_editor.frida import (
            inject_frida_gadget,
        )

        source_md5 = '6' * 32
        session = ApkEditorSession.objects.create(
            source_md5=source_md5,
            session_id='frida-no-application',
        )
        paths = self._fresh_paths(source_md5, session.session_id)
        paths.workspace.joinpath('smali/com/example').mkdir(parents=True)
        paths.workspace.joinpath('AndroidManifest.xml').write_text(
            '<manifest xmlns:android='
            '"http://schemas.android.com/apk/res/android" '
            'package="com.example">'
            '<application android:theme="@style/AppTheme"/>'
            '</manifest>',
            encoding='utf-8',
        )
        ensure_gadget_mock.return_value = (
            paths.workspace / 'lib/arm64-v8a/libfrida-gadget.so'
        )

        result = inject_frida_gadget(
            source_md5,
            session.session_id,
            ['arm64-v8a'],
        )

        generated = (
            paths.workspace
            / 'smali/com/example/MobSFApplication.smali'
        )
        manifest = paths.workspace.joinpath('AndroidManifest.xml').read_text(
            encoding='utf-8',
        )
        self.assertEqual(result['status'], 'ok')
        self.assertTrue(generated.is_file())
        self.assertIn('loadLibrary', generated.read_text(encoding='utf-8'))
        self.assertIn(
            'android:name="com.example.MobSFApplication"',
            manifest,
        )


class ApkEditorObfuscationTests(TestCase):
    """APK editor obfuscation tests."""

    def _fresh_paths(self, source_md5, session_id):
        from mobsf.StaticAnalyzer.views.android.apk_editor.paths import (
            editor_paths,
        )

        paths = editor_paths(source_md5, session_id)
        shutil.rmtree(paths.session_root, ignore_errors=True)
        self.addCleanup(
            shutil.rmtree,
            paths.session_root,
            ignore_errors=True,
        )
        return paths

    def test_obfuscate_assets_and_insert_noise_class(self):
        from mobsf.StaticAnalyzer.models import ApkEditorSession
        from mobsf.StaticAnalyzer.views.android.apk_editor.obfuscation import (
            obfuscate_session,
        )

        source_md5 = '4' * 32
        session = ApkEditorSession.objects.create(
            source_md5=source_md5,
            session_id='obf-session',
        )
        paths = self._fresh_paths(source_md5, session.session_id)
        (paths.workspace / 'assets').mkdir(parents=True)
        (paths.workspace / 'assets/config.json').write_text(
            '{}',
            encoding='utf-8',
        )
        (paths.workspace / 'smali/com/example').mkdir(parents=True)

        result = obfuscate_session(source_md5, session.session_id, {
            'assets': True,
            'anti_analysis': True,
            'smali': False,
            'resources': False,
            'frida_hide': False,
        })

        session.refresh_from_db()
        self.assertTrue(session.dirty)
        self.assertEqual(result['status'], 'ok')
        self.assertTrue(
            (paths.workspace / 'assets/a_config.json').is_file())
        self.assertTrue(
            (paths.workspace / 'smali/com/example/MobSFNoise.smali').is_file())
        self.assertTrue(
            (paths.session_root / 'mapping/obfuscation.json').is_file())

    def test_obfuscate_without_selected_options_leaves_session_clean(self):
        from mobsf.StaticAnalyzer.models import ApkEditorSession
        from mobsf.StaticAnalyzer.views.android.apk_editor.obfuscation import (
            obfuscate_session,
        )

        source_md5 = '5' * 32
        session = ApkEditorSession.objects.create(
            source_md5=source_md5,
            session_id='obf-no-options',
        )
        self._fresh_paths(source_md5, session.session_id)

        result = obfuscate_session(source_md5, session.session_id, {
            'assets': False,
            'anti_analysis': False,
            'smali': False,
            'resources': False,
            'frida_hide': False,
        })

        session.refresh_from_db()
        self.assertFalse(session.dirty)
        self.assertFalse(result['changed'])


class ApkEditorSaveTests(TestCase):
    """APK editor save/build tests."""

    def _fresh_paths(self, source_md5, session_id):
        from mobsf.StaticAnalyzer.views.android.apk_editor.paths import (
            editor_paths,
        )

        paths = editor_paths(source_md5, session_id)
        shutil.rmtree(paths.session_root, ignore_errors=True)
        self.addCleanup(
            shutil.rmtree,
            paths.session_root,
            ignore_errors=True,
        )
        return paths

    def test_save_clean_session_closes_and_deletes_directory(self):
        from mobsf.StaticAnalyzer.models import ApkEditorSession
        from mobsf.StaticAnalyzer.views.android.apk_editor.build import (
            save_session,
        )
        from mobsf.StaticAnalyzer.views.android.apk_editor.constants import (
            STATE_CLOSED_NO_CHANGES,
        )
        from mobsf.StaticAnalyzer.views.android.apk_editor.workspace import (
            create_workspace_dirs,
        )

        source_md5 = '9' * 32
        session = ApkEditorSession.objects.create(
            source_md5=source_md5,
            session_id='clean-save',
        )
        paths = self._fresh_paths(source_md5, session.session_id)
        create_workspace_dirs(paths)

        result = save_session(source_md5, session.session_id, {})

        session.refresh_from_db()
        self.assertEqual(result['state'], STATE_CLOSED_NO_CHANGES)
        self.assertEqual(session.state, STATE_CLOSED_NO_CHANGES)
        self.assertFalse(paths.session_root.exists())

    @patch(
        'mobsf.StaticAnalyzer.views.android.apk_editor.build.run_logged_command')
    def test_save_dirty_session_writes_output_and_marks_saved(
            self,
            run_mock):
        from mobsf.StaticAnalyzer.models import ApkEditorSession
        from mobsf.StaticAnalyzer.views.android.apk_editor.build import (
            save_session,
        )
        from mobsf.StaticAnalyzer.views.android.apk_editor.constants import (
            STATE_SAVED,
        )
        from mobsf.StaticAnalyzer.views.android.apk_editor.workspace import (
            create_workspace_dirs,
        )

        source_md5 = 'a' * 32
        session = ApkEditorSession.objects.create(
            source_md5=source_md5,
            session_id='dirty-save',
            dirty=True,
        )
        paths = self._fresh_paths(source_md5, session.session_id)
        create_workspace_dirs(paths)

        def fake_command(args, *_args, **_kwargs):
            if '-genkeypair' in args and '-keystore' in args:
                Path(args[args.index('-keystore') + 1]).write_bytes(
                    b'keystore')
            elif '-o' in args:
                Path(args[args.index('-o') + 1]).write_bytes(b'unsigned')
            elif Path(args[0]).name == 'zipalign':
                Path(args[-1]).write_bytes(Path(args[-2]).read_bytes())
            elif '--out' in args:
                Path(args[args.index('--out') + 1]).write_bytes(
                    Path(args[-1]).read_bytes())
            return Mock(returncode=0, stdout='', stderr='')

        run_mock.side_effect = fake_command

        result = save_session(
            source_md5,
            session.session_id,
            {'signing': 'debug'},
        )

        session.refresh_from_db()
        self.assertEqual(result['state'], STATE_SAVED)
        self.assertEqual(session.state, STATE_SAVED)
        self.assertTrue(
            paths.output.joinpath(f'{source_md5}-edited.apk').is_file())
        self.assertFalse(paths.workspace.exists())
        self.assertFalse(paths.build.exists())


class ApkEditorLogsTests(TestCase):
    """APK editor log endpoint tests."""

    def setUp(self):
        self.auth = api_key(settings.MOBSF_HOME)
        self.http_client = Client()

    def _login_superuser(self):
        user = get_user_model().objects.create_superuser(
            username='apk-editor-logs-admin',
            email='apk-editor-logs-admin@example.com',
            password='password',
        )
        self.http_client.force_login(user)

    def _write_log(self, source_md5, session_id):
        from mobsf.StaticAnalyzer.models import ApkEditorSession
        from mobsf.StaticAnalyzer.views.android.apk_editor.paths import (
            editor_paths,
        )
        from mobsf.StaticAnalyzer.views.android.apk_editor.workspace import (
            create_workspace_dirs,
        )

        session = ApkEditorSession.objects.create(
            source_md5=source_md5,
            session_id=session_id,
        )
        paths = editor_paths(source_md5, session.session_id)
        shutil.rmtree(paths.session_root, ignore_errors=True)
        self.addCleanup(
            shutil.rmtree,
            paths.session_root,
            ignore_errors=True,
        )
        create_workspace_dirs(paths)
        paths.log_file.write_text(
            'store_password=secret\n普通日志\n',
            encoding='utf-8',
        )
        return session

    def test_web_logs_endpoint_returns_redacted_log_lines(self):
        self._login_superuser()
        source_md5 = 'b' * 32
        session = self._write_log(source_md5, 'web-logs-session')

        response = self.http_client.get('/apk_editor/logs/', {
            'hash': source_md5,
            'session_id': session.session_id,
        })

        payload = json.loads(response.content)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload['status'], 'ok')
        self.assertNotIn('secret', payload['logs'])
        self.assertIn('普通日志', payload['logs'])

    def test_api_logs_endpoint_returns_redacted_log_lines(self):
        source_md5 = 'c' * 32
        session = self._write_log(source_md5, 'api-logs-session')

        response = self.http_client.get(
            '/api/v1/apk_editor/logs',
            {
                'hash': source_md5,
                'session_id': session.session_id,
            },
            HTTP_AUTHORIZATION=self.auth,
        )

        payload = json.loads(response.content)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload['status'], 'ok')
        self.assertNotIn('secret', payload['logs'])
        self.assertIn('普通日志', payload['logs'])


class ApkEditorSchemaCommandTests(TestCase):
    """APK editor deployment schema command tests."""

    @patch(
        'mobsf.StaticAnalyzer.management.commands.'
        'ensure_apk_editor_schema.connection')
    def test_ensure_apk_editor_schema_creates_missing_table(
            self,
            connection_mock):
        from django.core.management import call_command
        from mobsf.StaticAnalyzer.models import ApkEditorSession

        schema_editor = (
            connection_mock
            .schema_editor
            .return_value
            .__enter__
            .return_value
        )
        connection_mock.introspection.table_names.return_value = []

        call_command('ensure_apk_editor_schema')

        schema_editor.create_model.assert_called_once_with(ApkEditorSession)


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


class ApkEditorSessionServiceTests(TestCase):
    """APK editor session service tests."""

    def _create_source_apk(self, upload_dir, source_md5):
        source_dir = Path(upload_dir) / source_md5
        source_dir.mkdir(parents=True)
        source_apk = source_dir / f'{source_md5}.apk'
        source_apk.write_bytes(b'apk')
        return source_apk

    def _create_recent_scan(self, source_md5):
        from mobsf.StaticAnalyzer.models import RecentScansDB

        return RecentScansDB.objects.create(
            MD5=source_md5,
            SCAN_TYPE='apk',
            FILE_NAME='demo.apk',
        )

    def test_start_session_creates_active_session(self):
        from mobsf.StaticAnalyzer.models import ApkEditorSession
        from mobsf.StaticAnalyzer.views.android.apk_editor.constants import (
            STATE_ACTIVE,
        )
        from mobsf.StaticAnalyzer.views.android.apk_editor.session import (
            start_session,
        )

        source_md5 = 'a' * 32
        self._create_recent_scan(source_md5)

        with tempfile.TemporaryDirectory() as upload_dir:
            with self.settings(UPLD_DIR=upload_dir):
                self._create_source_apk(upload_dir, source_md5)
                with patch(
                        'mobsf.StaticAnalyzer.views.android.'
                        'apk_editor.session.decompile_apk') as decompile:
                    result = start_session(source_md5)

        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['hash'], source_md5)
        self.assertEqual(result['state'], STATE_ACTIVE)
        self.assertFalse(result['dirty'])
        self.assertEqual(ApkEditorSession.objects.count(), 1)
        decompile.assert_called_once()

    def test_start_session_accepts_uploaded_apk_without_recent_scan(self):
        from mobsf.StaticAnalyzer.models import (
            ApkEditorSession,
            RecentScansDB,
        )
        from mobsf.StaticAnalyzer.views.android.apk_editor.constants import (
            STATE_ACTIVE,
        )
        from mobsf.StaticAnalyzer.views.android.apk_editor.session import (
            start_session,
        )

        source_md5 = '9' * 32

        with tempfile.TemporaryDirectory() as upload_dir:
            with self.settings(UPLD_DIR=upload_dir):
                self._create_source_apk(upload_dir, source_md5)
                with patch(
                        'mobsf.StaticAnalyzer.views.android.'
                        'apk_editor.session.decompile_apk') as decompile:
                    result = start_session(source_md5)

        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['hash'], source_md5)
        self.assertEqual(result['state'], STATE_ACTIVE)
        self.assertEqual(ApkEditorSession.objects.count(), 1)
        self.assertEqual(RecentScansDB.objects.count(), 0)
        decompile.assert_called_once()

    def test_start_session_returns_existing_active_session(self):
        from mobsf.StaticAnalyzer.models import ApkEditorSession
        from mobsf.StaticAnalyzer.views.android.apk_editor.constants import (
            STATE_ACTIVE,
        )
        from mobsf.StaticAnalyzer.views.android.apk_editor.session import (
            start_session,
        )

        source_md5 = 'b' * 32
        self._create_recent_scan(source_md5)
        ApkEditorSession.objects.create(
            source_md5=source_md5,
            session_id='existing-session',
            state=STATE_ACTIVE,
        )

        with tempfile.TemporaryDirectory() as upload_dir:
            with self.settings(UPLD_DIR=upload_dir):
                self._create_source_apk(upload_dir, source_md5)
                with patch(
                        'mobsf.StaticAnalyzer.views.android.'
                        'apk_editor.session.decompile_apk') as decompile:
                    first = start_session(source_md5)
                    second = start_session(source_md5)

        self.assertEqual(first['session_id'], 'existing-session')
        self.assertEqual(second['session_id'], 'existing-session')
        self.assertEqual(ApkEditorSession.objects.count(), 1)
        decompile.assert_not_called()

    def test_start_session_returns_existing_save_failed_session(self):
        from mobsf.StaticAnalyzer.models import ApkEditorSession
        from mobsf.StaticAnalyzer.views.android.apk_editor.constants import (
            STATE_SAVE_FAILED,
        )
        from mobsf.StaticAnalyzer.views.android.apk_editor.session import (
            start_session,
        )

        source_md5 = 'e' * 32
        self._create_recent_scan(source_md5)
        ApkEditorSession.objects.create(
            source_md5=source_md5,
            session_id='save-failed-session',
            state=STATE_SAVE_FAILED,
        )

        with tempfile.TemporaryDirectory() as upload_dir:
            with self.settings(UPLD_DIR=upload_dir):
                self._create_source_apk(upload_dir, source_md5)
                with patch(
                        'mobsf.StaticAnalyzer.views.android.'
                        'apk_editor.session.decompile_apk') as decompile:
                    result = start_session(source_md5)

        self.assertEqual(result['session_id'], 'save-failed-session')
        self.assertEqual(result['state'], STATE_SAVE_FAILED)
        self.assertEqual(ApkEditorSession.objects.count(), 1)
        decompile.assert_not_called()

    def test_require_active_session_accepts_save_failed_session(self):
        from mobsf.StaticAnalyzer.models import ApkEditorSession
        from mobsf.StaticAnalyzer.views.android.apk_editor.constants import (
            STATE_SAVE_FAILED,
        )
        from mobsf.StaticAnalyzer.views.android.apk_editor.session import (
            require_active_session,
        )

        source_md5 = 'f' * 32
        session = ApkEditorSession.objects.create(
            source_md5=source_md5,
            session_id='save-failed-active-like',
            state=STATE_SAVE_FAILED,
        )

        result = require_active_session(source_md5, session.session_id)

        self.assertEqual(result, session)

    def test_discard_session_marks_state_and_deletes_files(self):
        from mobsf.StaticAnalyzer.models import ApkEditorSession
        from mobsf.StaticAnalyzer.views.android.apk_editor.constants import (
            STATE_ACTIVE,
            STATE_DISCARDED,
        )
        from mobsf.StaticAnalyzer.views.android.apk_editor.paths import (
            editor_paths,
        )
        from mobsf.StaticAnalyzer.views.android.apk_editor.session import (
            discard_session,
        )

        source_md5 = 'c' * 32
        session_id = 'discard-me'
        ApkEditorSession.objects.create(
            source_md5=source_md5,
            session_id=session_id,
            state=STATE_ACTIVE,
        )

        with tempfile.TemporaryDirectory() as upload_dir:
            with self.settings(UPLD_DIR=upload_dir):
                paths = editor_paths(source_md5, session_id)
                paths.session_root.mkdir(parents=True)
                result = discard_session(source_md5, session_id)

                self.assertFalse(paths.session_root.exists())

        session = ApkEditorSession.objects.get(session_id=session_id)
        self.assertEqual(result['state'], STATE_DISCARDED)
        self.assertEqual(session.state, STATE_DISCARDED)

    def test_source_lock_rejects_invalid_hash_without_creating_paths(self):
        from mobsf.StaticAnalyzer.views.android.apk_editor.locks import (
            source_lock,
        )

        with tempfile.TemporaryDirectory() as upload_dir:
            escape_name = f'{Path(upload_dir).name}-escape'
            escape_dir = Path(upload_dir).parent / escape_name
            with self.settings(UPLD_DIR=upload_dir):
                with self.assertRaises(ValueError):
                    with source_lock('not-md5'):
                        pass
                with self.assertRaises(ValueError):
                    with source_lock(f'../{escape_name}'):
                        pass

                self.assertEqual(list(Path(upload_dir).iterdir()), [])
                self.assertFalse(escape_dir.exists())

                with source_lock('1' * 32):
                    pass
                with self.assertRaises(ValueError):
                    with source_lock('../escape'):
                        pass

                self.assertEqual(
                    [path.name for path in Path(upload_dir).iterdir()],
                    ['1' * 32],
                )
                self.assertFalse(escape_dir.exists())

    def test_source_lock_replaces_stale_lock(self):
        from mobsf.StaticAnalyzer.views.android.apk_editor.locks import (
            source_lock,
        )

        source_md5 = '1' * 32
        with tempfile.TemporaryDirectory() as upload_dir:
            lock_file = (
                Path(upload_dir)
                / source_md5
                / 'apk_editor'
                / '.editor.lock'
            )
            lock_file.parent.mkdir(parents=True)
            lock_file.write_text('1', encoding='utf-8')
            old_time = 1
            os.utime(lock_file, (old_time, old_time))

            with self.settings(UPLD_DIR=upload_dir):
                with source_lock(source_md5, timeout=1, stale_after=1):
                    self.assertTrue(lock_file.exists())

            self.assertFalse(lock_file.exists())

    def test_mark_dirty_merges_metadata(self):
        from django.utils import timezone

        from mobsf.StaticAnalyzer.models import ApkEditorSession
        from mobsf.StaticAnalyzer.views.android.apk_editor.session import (
            mark_dirty,
        )

        old_updated_at = timezone.now()
        session = ApkEditorSession.objects.create(
            source_md5='d' * 32,
            session_id='dirty-session',
            dirty=False,
            operation_metadata={'manifest': {'changed': True}},
            updated_at=old_updated_at,
        )

        updated = mark_dirty(
            session,
            {
                'manifest': {'label': 'Demo'},
                'network': {'cleartext': False},
            },
        )

        self.assertTrue(updated.dirty)
        self.assertEqual(
            updated.operation_metadata,
            {
                'manifest': {
                    'changed': True,
                    'label': 'Demo',
                },
                'network': {'cleartext': False},
            },
        )
        self.assertGreater(updated.updated_at, old_updated_at)
