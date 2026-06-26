from pathlib import Path
from uuid import uuid4

from django.conf import settings
from django.utils import timezone

from mobsf.MobSF.utils import is_md5
from mobsf.StaticAnalyzer.models import ApkEditorSession
from mobsf.StaticAnalyzer.views.android.apk_editor.command import (
    append_log,
    redact_text,
)
from mobsf.StaticAnalyzer.views.android.apk_editor.constants import (
    ACTIVE_STATES,
    STATE_ACTIVE,
    STATE_DISCARDED,
)
from mobsf.StaticAnalyzer.views.android.apk_editor.locks import source_lock
from mobsf.StaticAnalyzer.views.android.apk_editor.paths import editor_paths
from mobsf.StaticAnalyzer.views.android.apk_editor.workspace import (
    decompile_apk,
    remove_session_dir,
)


def new_session_id():
    timestamp = timezone.now().strftime('%Y%m%d-%H%M%S')
    return f'{timestamp}-{uuid4().hex[:8]}'


def validate_source_apk(source_md5):
    if not is_md5(source_md5):
        raise ValueError('Invalid source hash')

    source_apk = Path(settings.UPLD_DIR) / source_md5 / f'{source_md5}.apk'
    if not source_apk.is_file():
        raise ValueError('Source APK not found')

    return source_apk


def active_session(source_md5):
    return (
        ApkEditorSession.objects.filter(
            source_md5=source_md5,
            state__in=ACTIVE_STATES,
        )
        .order_by('-updated_at', '-created_at', '-id')
        .first()
    )


def serialize_session(session):
    return {
        'status': 'ok',
        'hash': session.source_md5,
        'session_id': session.session_id,
        'state': session.state,
        'dirty': session.dirty,
        'output_apk': session.output_apk,
        'last_error': session.last_error,
        'operation_metadata': session.operation_metadata,
    }


def start_session(source_md5):
    with source_lock(source_md5):
        validate_source_apk(source_md5)

        existing = active_session(source_md5)
        if existing:
            return serialize_session(existing)

        session = ApkEditorSession.objects.create(
            source_md5=source_md5,
            session_id=new_session_id(),
            state=STATE_ACTIVE,
        )
        paths = editor_paths(source_md5, session.session_id)
        try:
            tools_dir = Path(settings.BASE_DIR) / 'StaticAnalyzer' / 'tools'
            decompile_apk(paths, tools_dir=tools_dir)
            append_log(paths.log_file, '编辑会话已创建')
            return serialize_session(session)
        except Exception as exp:
            session.state = STATE_DISCARDED
            session.last_error = str(exp)
            session.updated_at = timezone.now()
            session.save(update_fields=['state', 'last_error', 'updated_at'])
            remove_session_dir(paths)
            raise


def require_active_session(source_md5, session_id):
    session = ApkEditorSession.objects.filter(
        source_md5=source_md5,
        session_id=session_id,
    ).first()
    if not session:
        raise ValueError('Editor session not found')
    if session.state not in ACTIVE_STATES:
        raise ValueError('Editor session is not active')
    return session


def _deep_merge_dict(base, incoming):
    merged = dict(base or {})
    for key, value in (incoming or {}).items():
        current = merged.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            merged[key] = _deep_merge_dict(current, value)
        else:
            merged[key] = value
    return merged


def mark_dirty(session, metadata):
    operation_metadata = _deep_merge_dict(
        session.operation_metadata,
        metadata,
    )
    session.operation_metadata = operation_metadata
    session.dirty = True
    session.updated_at = timezone.now()
    session.save(update_fields=[
        'operation_metadata',
        'dirty',
        'updated_at',
    ])
    return session


def get_editor_status(source_md5, session_id=None):
    if session_id:
        session = ApkEditorSession.objects.filter(
            source_md5=source_md5,
            session_id=session_id,
        ).first()
    else:
        session = active_session(source_md5)

    if not session:
        return {'status': 'not_found'}
    return serialize_session(session)


def read_session_logs(source_md5, session_id):
    session = ApkEditorSession.objects.filter(
        source_md5=source_md5,
        session_id=session_id,
    ).first()
    if not session:
        raise ValueError('Editor session not found')

    paths = editor_paths(source_md5, session_id)
    if not paths.log_file.is_file():
        return ''
    return redact_text(paths.log_file.read_text(
        encoding='utf-8',
        errors='replace',
    ))


def discard_session(source_md5, session_id):
    with source_lock(source_md5):
        session = ApkEditorSession.objects.filter(
            source_md5=source_md5,
            session_id=session_id,
        ).first()
        if not session:
            raise ValueError('Editor session not found')

        paths = editor_paths(source_md5, session_id)
        remove_session_dir(paths)
        session.state = STATE_DISCARDED
        session.updated_at = timezone.now()
        session.save(update_fields=['state', 'updated_at'])
        return serialize_session(session)
