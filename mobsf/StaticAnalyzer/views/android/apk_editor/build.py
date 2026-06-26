from pathlib import Path

from django.conf import settings
from django.utils import timezone

from mobsf.MobSF.utils import find_java_binary
from mobsf.StaticAnalyzer.models import ApkEditorSession
from mobsf.StaticAnalyzer.views.android.apk_editor.command import (
    append_log,
    run_logged_command,
)
from mobsf.StaticAnalyzer.views.android.apk_editor.constants import (
    STATE_CLOSED_NO_CHANGES,
    STATE_SAVE_FAILED,
    STATE_SAVED,
    STATE_SAVING,
)
from mobsf.StaticAnalyzer.views.android.apk_editor.locks import source_lock
from mobsf.StaticAnalyzer.views.android.apk_editor.paths import editor_paths
from mobsf.StaticAnalyzer.views.android.apk_editor.session import (
    require_active_session,
    serialize_session,
)
from mobsf.StaticAnalyzer.views.android.apk_editor.workspace import (
    apktool_path,
    remove_build_workspace,
    remove_session_dir,
)


DEBUG_KEYSTORE_ALIAS = 'androiddebugkey'
DEBUG_KEYSTORE_PASSWORD = 'android'


def tools_dir():
    return Path(settings.BASE_DIR) / 'StaticAnalyzer' / 'tools'


def bundled_apksigner():
    return tools_dir() / 'apksigner.jar'


def bundled_zipalign():
    candidate = Path('/usr/bin/zipalign')
    if candidate.is_file():
        return str(candidate)
    return 'zipalign'


def ensure_output_exists(path, message):
    if not path.is_file():
        raise RuntimeError(message)
    return path


def ensure_debug_keystore(paths):
    keystore = paths.session_root / 'debug.keystore'
    if keystore.is_file():
        return keystore

    result = run_logged_command(
        [
            'keytool',
            '-genkeypair',
            '-v',
            '-keystore',
            str(keystore),
            '-storepass',
            DEBUG_KEYSTORE_PASSWORD,
            '-alias',
            DEBUG_KEYSTORE_ALIAS,
            '-keypass',
            DEBUG_KEYSTORE_PASSWORD,
            '-keyalg',
            'RSA',
            '-keysize',
            '2048',
            '-validity',
            '10000',
            '-dname',
            'CN=Android Debug,O=Android,C=US',
        ],
        paths.log_file,
        cwd=paths.session_root,
    )
    if result.returncode != 0:
        raise RuntimeError('debug keystore 生成失败')
    return ensure_output_exists(keystore, 'debug keystore 生成失败')


def build_unsigned(paths):
    unsigned_apk = paths.build / 'unsigned.apk'
    result = run_logged_command(
        [
            find_java_binary(),
            '-Djdk.util.zip.disableZip64ExtraFieldValidation=true',
            '-jar',
            apktool_path(tools_dir()),
            'b',
            str(paths.workspace),
            '-o',
            str(unsigned_apk),
        ],
        paths.log_file,
        cwd=paths.session_root,
    )
    if result.returncode != 0:
        raise RuntimeError('apktool 重打包失败')
    return ensure_output_exists(unsigned_apk, 'apktool 未生成重打包 APK')


def align_apk(paths, unsigned_apk):
    aligned_apk = paths.build / 'aligned.apk'
    result = run_logged_command(
        [
            bundled_zipalign(),
            '-p',
            '-f',
            '4',
            str(unsigned_apk),
            str(aligned_apk),
        ],
        paths.log_file,
        cwd=paths.session_root,
    )
    if result.returncode != 0:
        raise RuntimeError('zipalign 失败')
    return ensure_output_exists(aligned_apk, 'zipalign 未生成对齐 APK')


def sign_apk(paths, aligned_apk, signing_options):
    signing = (signing_options or {}).get('signing') or 'debug'
    if signing != 'debug':
        raise ValueError('Only debug signing is supported')

    keystore = ensure_debug_keystore(paths)
    final_apk = paths.output / f'{paths.source_md5}-edited.apk'
    result = run_logged_command(
        [
            find_java_binary(),
            '-jar',
            str(bundled_apksigner()),
            'sign',
            '--ks',
            str(keystore),
            '--ks-key-alias',
            DEBUG_KEYSTORE_ALIAS,
            '--ks-pass',
            f'pass:{DEBUG_KEYSTORE_PASSWORD}',
            '--key-pass',
            f'pass:{DEBUG_KEYSTORE_PASSWORD}',
            '--out',
            str(final_apk),
            str(aligned_apk),
        ],
        paths.log_file,
        cwd=paths.session_root,
    )
    if result.returncode != 0:
        raise RuntimeError('apksigner 签名失败')
    return ensure_output_exists(final_apk, 'apksigner 未生成签名 APK')


def save_session(source_md5, session_id, signing_options):
    """Save an APK editor session and produce a signed APK when dirty."""
    with source_lock(source_md5):
        session = require_active_session(source_md5, session_id)
        paths = editor_paths(source_md5, session_id)

        if not session.dirty:
            remove_session_dir(paths)
            session.state = STATE_CLOSED_NO_CHANGES
            session.updated_at = timezone.now()
            session.save(update_fields=['state', 'updated_at'])
            return serialize_session(session)

        try:
            session.state = STATE_SAVING
            session.updated_at = timezone.now()
            session.save(update_fields=['state', 'updated_at'])
            paths.build.mkdir(parents=True, exist_ok=True)
            paths.output.mkdir(parents=True, exist_ok=True)
            append_log(paths.log_file, '开始保存编辑后的 APK')

            unsigned_apk = build_unsigned(paths)
            aligned_apk = align_apk(paths, unsigned_apk)
            final_apk = sign_apk(paths, aligned_apk, signing_options)
            remove_build_workspace(paths)

            now = timezone.now()
            session.state = STATE_SAVED
            session.output_apk = str(final_apk)
            session.saved_at = now
            session.updated_at = now
            session.save(update_fields=[
                'state',
                'output_apk',
                'saved_at',
                'updated_at',
            ])
            append_log(paths.log_file, f'保存完成: {final_apk}')
            return serialize_session(session)
        except Exception as exp:
            session.state = STATE_SAVE_FAILED
            session.last_error = str(exp)
            session.updated_at = timezone.now()
            session.save(update_fields=[
                'state',
                'last_error',
                'updated_at',
            ])
            append_log(paths.log_file, f'保存失败: {exp}')
            raise


def saved_output_path(source_md5, session_id):
    session = ApkEditorSession.objects.filter(
        source_md5=source_md5,
        session_id=session_id,
        state=STATE_SAVED,
    ).first()
    if not session or not session.output_apk:
        raise ValueError('Saved APK not found')

    paths = editor_paths(source_md5, session_id)
    output_apk = Path(session.output_apk)
    try:
        output_apk.relative_to(paths.output)
    except ValueError as exp:
        raise ValueError('Saved APK path is invalid') from exp
    return ensure_output_exists(output_apk, 'Saved APK not found')
