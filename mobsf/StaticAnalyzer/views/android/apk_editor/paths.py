import re
from dataclasses import dataclass
from pathlib import Path

from django.conf import settings

from mobsf.StaticAnalyzer.views.android.apk_editor.constants import (
    BUILD_DIR,
    EDITOR_DIR,
    LOG_DIR,
    LOG_FILE,
    OUTPUT_DIR,
    WORKSPACE_DIR,
)


SOURCE_MD5_RE = re.compile(r'^[0-9a-fA-F]{32}$')
SESSION_ID_RE = re.compile(r'^[A-Za-z0-9_-]{1,80}$')


@dataclass(frozen=True)
class ApkEditorPaths:
    source_md5: str
    session_id: str
    source_dir: Path
    source_apk: Path
    session_root: Path
    workspace: Path
    build: Path
    output: Path
    logs: Path
    log_file: Path


def editor_paths(source_md5, session_id):
    if not isinstance(source_md5, str) or not SOURCE_MD5_RE.fullmatch(
            source_md5):
        raise ValueError('source_md5 must be a 32 character hex string')
    if not isinstance(session_id, str) or not SESSION_ID_RE.fullmatch(
            session_id):
        raise ValueError(
            'session_id must be 1-80 characters: letters, numbers, '
            'underscore, or hyphen')

    source_dir = Path(settings.UPLD_DIR) / source_md5
    session_root = source_dir / EDITOR_DIR / session_id
    logs = session_root / LOG_DIR

    return ApkEditorPaths(
        source_md5=source_md5,
        session_id=session_id,
        source_dir=source_dir,
        source_apk=source_dir / f'{source_md5}.apk',
        session_root=session_root,
        workspace=session_root / WORKSPACE_DIR,
        build=session_root / BUILD_DIR,
        output=session_root / OUTPUT_DIR,
        logs=logs,
        log_file=logs / LOG_FILE,
    )
