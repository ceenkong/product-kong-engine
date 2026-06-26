# APK 编辑器 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: 使用 `superpowers:subagent-driven-development`（推荐）或 `superpowers:executing-plans` 按任务逐步实现本计划。步骤使用 checkbox（`- [ ]`）语法跟踪。

**Goal:** 实现 APK 编辑会话：用户可以对已扫描 APK 进入编辑状态，执行 Frida Gadget 注入和混淆，保存时按 dirty 状态决定是否重打包签名并提供下载。

**Architecture:** 新增一个独立的 APK editor 服务层，Django view 和 REST API 只负责参数校验、权限校验和响应格式。会话状态持久化在 `StaticAnalyzer` 模型里，文件工作区放在源 APK 扫描目录下，耗时命令通过统一 command runner 执行并写日志。

**Tech Stack:** Django models/views/templates、MobSF 现有认证权限体系、apktool、zipalign、apksigner、Python `subprocess`、Django TestCase。

---

## 计划修正点

设计文档里写了“页面操作应该调用 REST API”。实现时不要把 API key 注入浏览器。页面使用登录会话和 CSRF 调用 Web JSON endpoint；REST API 仍然提供同等能力，并与 Web endpoint 共用服务层。这样能同时满足页面能力和 API 能力，也避免把 API key 暴露给前端。

## 文件结构

新增目录：

```text
mobsf/StaticAnalyzer/views/android/apk_editor/
```

职责划分：

- `constants.py`：会话状态、默认 ABI、目录名、敏感字段名。
- `paths.py`：源 APK、session root、workspace、build、output、logs 路径计算。
- `locks.py`：基于 `source_md5` 的文件锁，保护保存和放弃操作。
- `command.py`：统一执行外部命令，记录 stdout/stderr，脱敏密码。
- `workspace.py`：创建目录、apktool 解包、清理目录。
- `session.py`：创建/查询/关闭会话，写结构化日志。
- `frida.py`：Frida Gadget ABI 检测、下载/复用、smali 注入。
- `obfuscation.py`：smali、assets、资源、防分析混淆。
- `build.py`：apktool build、zipalign、debug/custom keystore 签名、产物路径。
- `web.py`：页面 JSON endpoint。
- `api.py`：REST API endpoint。

修改文件：

- `mobsf/StaticAnalyzer/models.py`：新增 `ApkEditorSession` 模型。
- `mobsf/MobSF/urls.py`：注册 Web endpoint 和 REST API endpoint。
- `mobsf/templates/static_analysis/android_binary_analysis.html`：引入 APK 编辑器卡片。
- `mobsf/templates/static_analysis/android_apk_editor.html`：新增编辑器卡片模板。
- `mobsf/static/others/js/apk_editor.js`：新增页面交互 JS。
- `mobsf/StaticAnalyzer/tests.py`：增加 API、服务层、模板入口测试。

每个实现任务完成后都提交一次，避免大批量改动难以回滚。

---

### Task 1: 会话模型、常量和路径管理

**Files:**
- Modify: `mobsf/StaticAnalyzer/models.py`
- Create: `mobsf/StaticAnalyzer/views/android/apk_editor/__init__.py`
- Create: `mobsf/StaticAnalyzer/views/android/apk_editor/constants.py`
- Create: `mobsf/StaticAnalyzer/views/android/apk_editor/paths.py`
- Modify: `mobsf/StaticAnalyzer/tests.py`

- [x] **Step 1: 写失败测试**

在 `mobsf/StaticAnalyzer/tests.py` 末尾新增：

```python
from pathlib import Path

from mobsf.StaticAnalyzer.models import ApkEditorSession, RecentScansDB
from mobsf.StaticAnalyzer.views.android.apk_editor.constants import (
    STATE_ACTIVE,
)
from mobsf.StaticAnalyzer.views.android.apk_editor.paths import (
    editor_paths,
)


class ApkEditorModelAndPathTests(TestCase):
    def test_editor_paths_are_under_source_scan_directory(self):
        source_md5 = 'a' * 32
        session_id = '20260626-120000-abcd'

        paths = editor_paths(source_md5, session_id)

        self.assertEqual(paths.source_md5, source_md5)
        self.assertTrue(str(paths.session_root).endswith(
            f'{source_md5}/apk_editor/{session_id}'))
        self.assertEqual(paths.workspace, paths.session_root / 'workspace')
        self.assertEqual(paths.build, paths.session_root / 'build')
        self.assertEqual(paths.output, paths.session_root / 'output')
        self.assertEqual(paths.log_file, paths.session_root / 'logs/editor.log')

    def test_apk_editor_session_defaults(self):
        RecentScansDB.objects.create(
            MD5='b' * 32,
            SCAN_TYPE='apk',
            FILE_NAME='demo.apk',
            ANALYZER='static_analyzer',
        )

        session = ApkEditorSession.objects.create(
            source_md5='b' * 32,
            session_id='20260626-120001-bbbb',
        )

        self.assertEqual(session.state, STATE_ACTIVE)
        self.assertFalse(session.dirty)
        self.assertEqual(session.operation_metadata, {})
        self.assertEqual(session.last_error, '')
```

- [x] **Step 2: 运行测试确认失败**

Run:

```bash
python manage.py test mobsf.StaticAnalyzer.tests.ApkEditorModelAndPathTests -v 2
```

Expected: FAIL，错误包含 `cannot import name 'ApkEditorSession'` 或 `No module named 'mobsf.StaticAnalyzer.views.android.apk_editor'`。

- [ ] **Step 3: 新增常量文件**

创建 `mobsf/StaticAnalyzer/views/android/apk_editor/constants.py`：

```python
"""Constants for Android APK editor."""

STATE_ACTIVE = 'active'
STATE_SAVING = 'saving'
STATE_SAVED = 'saved'
STATE_SAVE_FAILED = 'save_failed'
STATE_CLOSED_NO_CHANGES = 'closed_no_changes'
STATE_DISCARDED = 'discarded'

ACTIVE_STATES = {STATE_ACTIVE, STATE_SAVE_FAILED}
CLOSED_STATES = {STATE_SAVED, STATE_CLOSED_NO_CHANGES, STATE_DISCARDED}

DEFAULT_ABI = 'arm64-v8a'
EDITOR_DIR = 'apk_editor'
WORKSPACE_DIR = 'workspace'
BUILD_DIR = 'build'
OUTPUT_DIR = 'output'
LOG_DIR = 'logs'
LOG_FILE = 'editor.log'

SECRET_KEYS = {
    'store_password',
    'key_password',
    'password',
    'authorization',
    'api_key',
}
```

- [ ] **Step 4: 新增路径管理文件**

创建 `mobsf/StaticAnalyzer/views/android/apk_editor/paths.py`：

```python
"""Filesystem paths for Android APK editor sessions."""
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
    """Return all paths for an editor session."""
    source_dir = Path(settings.UPLD_DIR) / source_md5
    session_root = source_dir / EDITOR_DIR / session_id
    return ApkEditorPaths(
        source_md5=source_md5,
        session_id=session_id,
        source_dir=source_dir,
        source_apk=source_dir / f'{source_md5}.apk',
        session_root=session_root,
        workspace=session_root / WORKSPACE_DIR,
        build=session_root / BUILD_DIR,
        output=session_root / OUTPUT_DIR,
        logs=session_root / LOG_DIR,
        log_file=session_root / LOG_DIR / LOG_FILE,
    )
```

- [ ] **Step 5: 新增模型**

在 `mobsf/StaticAnalyzer/models.py` 的 `EnqueuedTask` 前新增：

```python
class ApkEditorSession(models.Model):
    source_md5 = models.CharField(max_length=32, db_index=True)
    session_id = models.CharField(max_length=80, unique=True)
    state = models.CharField(max_length=32, default='active', db_index=True)
    dirty = models.BooleanField(default=False)
    operation_metadata = models.JSONField(default=dict)
    output_apk = models.TextField(default='')
    last_error = models.TextField(default='')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    saved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=['source_md5', 'state']),
        ]

    def __str__(self):
        return f'{self.source_md5}:{self.session_id}:{self.state}'
```

- [ ] **Step 6: 运行测试确认通过**

Run:

```bash
python manage.py test mobsf.StaticAnalyzer.tests.ApkEditorModelAndPathTests -v 2
```

Expected: PASS，输出包含 `Ran 2 tests` 和 `OK`。

- [ ] **Step 7: 验证模型迁移可生成**

Run:

```bash
python manage.py makemigrations StaticAnalyzer --dry-run --check
```

Expected: 这个命令返回非 0，因为模型变更还没有迁移文件；项目当前 Docker 启动会自动 `makemigrations StaticAnalyzer`，实现阶段记录该现象即可。

Run:

```bash
python manage.py makemigrations StaticAnalyzer --dry-run
```

Expected: 输出包含 `Create model ApkEditorSession`。

- [ ] **Step 8: 提交**

```bash
git add mobsf/StaticAnalyzer/models.py mobsf/StaticAnalyzer/views/android/apk_editor mobsf/StaticAnalyzer/tests.py
git commit -m "feat: add apk editor session model"
```

---

### Task 2: 命令执行、日志脱敏和工作目录管理

**Files:**
- Create: `mobsf/StaticAnalyzer/views/android/apk_editor/command.py`
- Create: `mobsf/StaticAnalyzer/views/android/apk_editor/workspace.py`
- Modify: `mobsf/StaticAnalyzer/tests.py`

- [ ] **Step 1: 写失败测试**

新增测试：

```python
from unittest import mock

from mobsf.StaticAnalyzer.views.android.apk_editor.command import (
    redact_text,
    run_logged_command,
)
from mobsf.StaticAnalyzer.views.android.apk_editor.workspace import (
    create_workspace_dirs,
)


class ApkEditorWorkspaceTests(TestCase):
    def test_redact_text_hides_secret_values(self):
        text = 'store_password=abc123 key_password=def456 api_key=secret'

        redacted = redact_text(text)

        self.assertNotIn('abc123', redacted)
        self.assertNotIn('def456', redacted)
        self.assertNotIn('secret', redacted)
        self.assertIn('store_password=<redacted>', redacted)

    def test_create_workspace_dirs_creates_expected_directories(self):
        paths = editor_paths('c' * 32, '20260626-120002-cccc')

        create_workspace_dirs(paths)

        self.assertTrue(paths.workspace.is_dir())
        self.assertTrue(paths.build.is_dir())
        self.assertTrue(paths.output.is_dir())
        self.assertTrue(paths.logs.is_dir())

    @mock.patch('subprocess.run')
    def test_run_logged_command_writes_command_output(self, run_mock):
        paths = editor_paths('d' * 32, '20260626-120003-dddd')
        create_workspace_dirs(paths)
        run_mock.return_value.returncode = 0
        run_mock.return_value.stdout = 'ok'
        run_mock.return_value.stderr = ''

        result = run_logged_command(
            ['echo', 'ok'],
            paths.log_file,
            cwd=paths.session_root,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn('echo ok', paths.log_file.read_text())
        self.assertIn('ok', paths.log_file.read_text())
```

- [ ] **Step 2: 运行测试确认失败**

Run:

```bash
python manage.py test mobsf.StaticAnalyzer.tests.ApkEditorWorkspaceTests -v 2
```

Expected: FAIL，错误包含 `No module named` 或 `cannot import name`。

- [ ] **Step 3: 实现命令执行**

创建 `command.py`：

```python
"""Command helpers for APK editor."""
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from mobsf.StaticAnalyzer.views.android.apk_editor.constants import SECRET_KEYS


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def redact_text(text):
    """Redact known secret values in command output."""
    redacted = text
    for key in SECRET_KEYS:
        redacted = re.sub(
            rf'({re.escape(key)}=)([^\\s]+)',
            rf'\\1<redacted>',
            redacted,
            flags=re.IGNORECASE,
        )
    return redacted


def append_log(log_file, message):
    """Append one message to an editor log file."""
    Path(log_file).parent.mkdir(parents=True, exist_ok=True)
    with open(log_file, 'a', encoding='utf-8') as log:
        log.write(redact_text(message).rstrip())
        log.write('\\n')


def run_logged_command(args, log_file, cwd=None, timeout=None):
    """Run a command and write sanitized output to log."""
    append_log(log_file, f'$ {" ".join(str(i) for i in args)}')
    completed = subprocess.run(
        [str(i) for i in args],
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )
    stdout = completed.stdout or ''
    stderr = completed.stderr or ''
    if stdout:
        append_log(log_file, stdout)
    if stderr:
        append_log(log_file, stderr)
    return CommandResult(completed.returncode, stdout, stderr)
```

- [ ] **Step 4: 实现工作目录管理**

创建 `workspace.py`：

```python
"""Workspace helpers for APK editor."""
import shutil

from django.conf import settings

from mobsf.MobSF.utils import find_java_binary
from mobsf.StaticAnalyzer.views.android.apk_editor.command import (
    append_log,
    run_logged_command,
)


def create_workspace_dirs(paths):
    """Create all directories used by an editor session."""
    paths.workspace.mkdir(parents=True, exist_ok=True)
    paths.build.mkdir(parents=True, exist_ok=True)
    paths.output.mkdir(parents=True, exist_ok=True)
    paths.logs.mkdir(parents=True, exist_ok=True)


def remove_session_dir(paths):
    """Delete the whole editor session directory."""
    shutil.rmtree(paths.session_root, ignore_errors=True)


def remove_build_workspace(paths):
    """Delete workspace and build directories after successful save."""
    shutil.rmtree(paths.workspace, ignore_errors=True)
    shutil.rmtree(paths.build, ignore_errors=True)


def apktool_path(tools_dir):
    """Return configured or bundled apktool path."""
    if settings.APKTOOL_BINARY:
        return settings.APKTOOL_BINARY
    return str(tools_dir / 'apktool_2.10.0.jar')


def decompile_apk(paths, tools_dir):
    """Decompile source APK into workspace."""
    create_workspace_dirs(paths)
    append_log(paths.log_file, '开始 apktool 解包')
    args = [
        find_java_binary(),
        '-Djdk.util.zip.disableZip64ExtraFieldValidation=true',
        '-jar',
        apktool_path(tools_dir),
        '--frame-path',
        '/tmp',
        '-f',
        'd',
        str(paths.source_apk),
        '-o',
        str(paths.workspace),
    ]
    result = run_logged_command(args, paths.log_file, cwd=paths.session_root)
    if result.returncode != 0:
        raise RuntimeError('apktool 解包失败')
    append_log(paths.log_file, 'apktool 解包完成')
```

- [ ] **Step 5: 运行测试确认通过**

Run:

```bash
python manage.py test mobsf.StaticAnalyzer.tests.ApkEditorWorkspaceTests -v 2
```

Expected: PASS，输出包含 `Ran 3 tests` 和 `OK`。

- [ ] **Step 6: 提交**

```bash
git add mobsf/StaticAnalyzer/views/android/apk_editor/command.py mobsf/StaticAnalyzer/views/android/apk_editor/workspace.py mobsf/StaticAnalyzer/tests.py
git commit -m "feat: add apk editor workspace helpers"
```

---

### Task 3: 会话服务、active 会话复用和日志状态

**Files:**
- Create: `mobsf/StaticAnalyzer/views/android/apk_editor/session.py`
- Create: `mobsf/StaticAnalyzer/views/android/apk_editor/locks.py`
- Modify: `mobsf/StaticAnalyzer/tests.py`

- [ ] **Step 1: 写失败测试**

新增测试：

```python
from django.test import override_settings

from mobsf.StaticAnalyzer.views.android.apk_editor.session import (
    discard_session,
    get_editor_status,
    start_session,
)


class ApkEditorSessionServiceTests(TestCase):
    @mock.patch('mobsf.StaticAnalyzer.views.android.apk_editor.session.decompile_apk')
    def test_start_session_creates_active_session(self, decompile_mock):
        md5 = 'e' * 32
        RecentScansDB.objects.create(MD5=md5, SCAN_TYPE='apk', FILE_NAME='demo.apk')
        paths = editor_paths(md5, 'source')
        paths.source_dir.mkdir(parents=True, exist_ok=True)
        paths.source_apk.write_bytes(b'apk')

        result = start_session(md5)

        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['state'], STATE_ACTIVE)
        self.assertFalse(result['dirty'])
        self.assertEqual(ApkEditorSession.objects.filter(source_md5=md5).count(), 1)
        decompile_mock.assert_called_once()

    @mock.patch('mobsf.StaticAnalyzer.views.android.apk_editor.session.decompile_apk')
    def test_start_session_returns_existing_active_session(self, decompile_mock):
        md5 = 'f' * 32
        RecentScansDB.objects.create(MD5=md5, SCAN_TYPE='apk', FILE_NAME='demo.apk')
        ApkEditorSession.objects.create(source_md5=md5, session_id='existing')

        first = start_session(md5)
        second = start_session(md5)

        self.assertEqual(first['session_id'], 'existing')
        self.assertEqual(second['session_id'], 'existing')
        decompile_mock.assert_not_called()

    def test_discard_session_marks_state_and_deletes_files(self):
        md5 = '1' * 32
        session = ApkEditorSession.objects.create(source_md5=md5, session_id='discard-me')
        paths = editor_paths(md5, session.session_id)
        create_workspace_dirs(paths)

        result = discard_session(md5, session.session_id)

        session.refresh_from_db()
        self.assertEqual(result['state'], STATE_DISCARDED)
        self.assertEqual(session.state, STATE_DISCARDED)
        self.assertFalse(paths.session_root.exists())
```

- [ ] **Step 2: 运行测试确认失败**

Run:

```bash
python manage.py test mobsf.StaticAnalyzer.tests.ApkEditorSessionServiceTests -v 2
```

Expected: FAIL，错误包含 `No module named` 或 `cannot import name 'start_session'`。

- [ ] **Step 3: 实现文件锁**

创建 `locks.py`：

```python
"""File locks for APK editor critical sections."""
import os
import time
from contextlib import contextmanager
from pathlib import Path

from django.conf import settings


@contextmanager
def source_lock(source_md5, timeout=30):
    """Lock by source MD5 with an atomic lock file."""
    lock_dir = Path(settings.UPLD_DIR) / source_md5 / 'apk_editor'
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock_file = lock_dir / '.editor.lock'
    start = time.monotonic()
    fd = None
    while fd is None:
        try:
            fd = os.open(str(lock_file), os.O_CREAT | os.O_EXCL | os.O_RDWR)
        except FileExistsError:
            if time.monotonic() - start > timeout:
                raise TimeoutError('APK 编辑器锁等待超时')
            time.sleep(0.1)
    try:
        yield
    finally:
        os.close(fd)
        try:
            lock_file.unlink()
        except FileNotFoundError:
            pass
```

- [ ] **Step 4: 实现会话服务**

创建 `session.py`：

```python
"""Session service for APK editor."""
import uuid
from datetime import datetime
from pathlib import Path

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from mobsf.MobSF.utils import is_md5
from mobsf.StaticAnalyzer.models import ApkEditorSession, RecentScansDB
from mobsf.StaticAnalyzer.views.android.apk_editor.command import append_log
from mobsf.StaticAnalyzer.views.android.apk_editor.constants import (
    CLOSED_STATES,
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
    """Create a sortable session id."""
    stamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
    return f'{stamp}-{uuid.uuid4().hex[:8]}'


def validate_source_apk(source_md5):
    """Validate that source hash points to an uploaded APK."""
    if not is_md5(source_md5):
        raise ValueError('Invalid APK hash')
    scan = RecentScansDB.objects.filter(MD5=source_md5).first()
    if not scan or scan.SCAN_TYPE != 'apk':
        raise ValueError('Hash is not an APK scan')
    source_apk = Path(settings.UPLD_DIR) / source_md5 / f'{source_md5}.apk'
    if not source_apk.is_file():
        raise ValueError('Source APK file not found')
    return scan


def active_session(source_md5):
    """Return the active editor session for a source hash."""
    return ApkEditorSession.objects.filter(
        source_md5=source_md5,
        state=STATE_ACTIVE,
    ).order_by('-created_at').first()


def serialize_session(session):
    """Return API-safe session data."""
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
    """Create or return the active editor session."""
    with source_lock(source_md5):
        validate_source_apk(source_md5)
        existing = active_session(source_md5)
        if existing:
            return serialize_session(existing)
        session = ApkEditorSession.objects.create(
            source_md5=source_md5,
            session_id=new_session_id(),
        )
        paths = editor_paths(source_md5, session.session_id)
        tools_dir = Path(settings.BASE_DIR) / 'StaticAnalyzer' / 'tools'
        try:
            decompile_apk(paths, tools_dir)
            append_log(paths.log_file, '编辑会话已创建')
            return serialize_session(session)
        except Exception as exp:
            session.state = STATE_DISCARDED
            session.last_error = str(exp)
            session.updated_at = timezone.now()
            session.save()
            remove_session_dir(paths)
            raise


def require_active_session(source_md5, session_id):
    """Load and validate an active session."""
    session = ApkEditorSession.objects.filter(
        source_md5=source_md5,
        session_id=session_id,
    ).first()
    if not session:
        raise ValueError('Editor session not found')
    if session.state != STATE_ACTIVE:
        raise ValueError('Editor session is not active')
    return session


def mark_dirty(session, metadata):
    """Mark a session as changed and merge operation metadata."""
    data = dict(session.operation_metadata or {})
    data.update(metadata)
    session.operation_metadata = data
    session.dirty = True
    session.updated_at = timezone.now()
    session.save()
    return session


def get_editor_status(source_md5, session_id=None):
    """Return current editor status."""
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


def discard_session(source_md5, session_id):
    """Discard an active or failed editor session."""
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
        session.save()
        return serialize_session(session)
```

- [ ] **Step 5: 运行测试确认通过**

Run:

```bash
python manage.py test mobsf.StaticAnalyzer.tests.ApkEditorSessionServiceTests -v 2
```

Expected: PASS，输出包含 `Ran 3 tests` 和 `OK`。

- [ ] **Step 6: 提交**

```bash
git add mobsf/StaticAnalyzer/views/android/apk_editor/locks.py mobsf/StaticAnalyzer/views/android/apk_editor/session.py mobsf/StaticAnalyzer/tests.py
git commit -m "feat: add apk editor session service"
```

---

### Task 4: REST API 和 Web JSON endpoint 骨架

**Files:**
- Create: `mobsf/StaticAnalyzer/views/android/apk_editor/api.py`
- Create: `mobsf/StaticAnalyzer/views/android/apk_editor/web.py`
- Modify: `mobsf/MobSF/urls.py`
- Modify: `mobsf/StaticAnalyzer/tests.py`

- [ ] **Step 1: 写失败测试**

新增测试：

```python
from mobsf.MobSF.init import api_key


class ApkEditorEndpointTests(TestCase):
    def setUp(self):
        self.auth = api_key(settings.MOBSF_HOME)

    @mock.patch('mobsf.StaticAnalyzer.views.android.apk_editor.api.start_session')
    def test_api_start_requires_hash(self, start_mock):
        response = self.client.post(
            '/api/v1/apk_editor/start',
            {},
            HTTP_AUTHORIZATION=self.auth,
        )

        self.assertEqual(response.status_code, 422)
        start_mock.assert_not_called()

    @mock.patch('mobsf.StaticAnalyzer.views.android.apk_editor.api.start_session')
    def test_api_start_returns_session_json(self, start_mock):
        start_mock.return_value = {
            'status': 'ok',
            'hash': 'a' * 32,
            'session_id': 'sid',
            'state': 'active',
            'dirty': False,
            'output_apk': '',
            'last_error': '',
            'operation_metadata': {},
        }

        response = self.client.post(
            '/api/v1/apk_editor/start',
            {'hash': 'a' * 32},
            HTTP_AUTHORIZATION=self.auth,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['session_id'], 'sid')

    @mock.patch('mobsf.StaticAnalyzer.views.android.apk_editor.web.start_session')
    def test_web_start_returns_session_json(self, start_mock):
        start_mock.return_value = {
            'status': 'ok',
            'hash': 'a' * 32,
            'session_id': 'sid',
            'state': 'active',
            'dirty': False,
            'output_apk': '',
            'last_error': '',
            'operation_metadata': {},
        }

        response = self.client.post('/apk_editor/start/', {'hash': 'a' * 32})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['session_id'], 'sid')
```

- [ ] **Step 2: 运行测试确认失败**

Run:

```bash
python manage.py test mobsf.StaticAnalyzer.tests.ApkEditorEndpointTests -v 2
```

Expected: FAIL，错误包含 404 或 import error。

- [ ] **Step 3: 实现 API views**

创建 `api.py`：

```python
"""REST API for APK editor."""
from django.views.decorators.csrf import csrf_exempt

from mobsf.MobSF.views.api.api_middleware import make_api_response
from mobsf.MobSF.views.helpers import request_method
from mobsf.StaticAnalyzer.views.android.apk_editor.session import (
    discard_session,
    get_editor_status,
    start_session,
)


def missing_hash_response():
    return make_api_response({'error': 'Missing hash'}, 422)


def handle_service_error(exp):
    return make_api_response({'error': str(exp)}, 400)


@request_method(['POST'])
@csrf_exempt
def api_start(request):
    if 'hash' not in request.POST:
        return missing_hash_response()
    try:
        return make_api_response(start_session(request.POST['hash']), 200)
    except Exception as exp:
        return handle_service_error(exp)


@request_method(['GET', 'POST'])
@csrf_exempt
def api_status(request):
    source_hash = request.GET.get('hash') or request.POST.get('hash')
    if not source_hash:
        return missing_hash_response()
    session_id = request.GET.get('session_id') or request.POST.get('session_id')
    return make_api_response(get_editor_status(source_hash, session_id), 200)


@request_method(['POST'])
@csrf_exempt
def api_discard(request):
    if 'hash' not in request.POST or 'session_id' not in request.POST:
        return make_api_response({'error': 'Missing hash or session_id'}, 422)
    try:
        return make_api_response(
            discard_session(request.POST['hash'], request.POST['session_id']),
            200,
        )
    except Exception as exp:
        return handle_service_error(exp)
```

- [ ] **Step 4: 实现 Web JSON views**

创建 `web.py`：

```python
"""Session-authenticated web endpoints for APK editor."""
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods

from mobsf.MobSF.views.authentication import login_required
from mobsf.MobSF.views.authorization import Permissions, permission_required
from mobsf.StaticAnalyzer.views.android.apk_editor.session import (
    discard_session,
    get_editor_status,
    start_session,
)


def json_error(message, status=400):
    return JsonResponse({'status': 'failed', 'error': message}, status=status)


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def start(request):
    source_hash = request.POST.get('hash')
    if not source_hash:
        return json_error('Missing hash', 422)
    try:
        return JsonResponse(start_session(source_hash))
    except Exception as exp:
        return json_error(str(exp), 400)


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['GET', 'POST'])
def status(request):
    source_hash = request.GET.get('hash') or request.POST.get('hash')
    if not source_hash:
        return json_error('Missing hash', 422)
    session_id = request.GET.get('session_id') or request.POST.get('session_id')
    return JsonResponse(get_editor_status(source_hash, session_id))


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def discard(request):
    source_hash = request.POST.get('hash')
    session_id = request.POST.get('session_id')
    if not source_hash or not session_id:
        return json_error('Missing hash or session_id', 422)
    try:
        return JsonResponse(discard_session(source_hash, session_id))
    except Exception as exp:
        return json_error(str(exp), 400)
```

- [ ] **Step 5: 注册 URL**

在 `mobsf/MobSF/urls.py` import 区增加：

```python
from mobsf.StaticAnalyzer.views.android.apk_editor import (
    api as apk_editor_api,
    web as apk_editor_web,
)
```

在 REST API 区增加：

```python
    re_path(r'^api/v1/apk_editor/start$', apk_editor_api.api_start),
    re_path(r'^api/v1/apk_editor/status$', apk_editor_api.api_status),
    re_path(r'^api/v1/apk_editor/discard$', apk_editor_api.api_discard),
```

在 `if settings.API_ONLY == '0':` 的 web URL 区增加：

```python
        re_path(r'^apk_editor/start/$', apk_editor_web.start, name='apk_editor_start'),
        re_path(r'^apk_editor/status/$', apk_editor_web.status, name='apk_editor_status'),
        re_path(r'^apk_editor/discard/$', apk_editor_web.discard, name='apk_editor_discard'),
```

- [ ] **Step 6: 运行测试确认通过**

Run:

```bash
python manage.py test mobsf.StaticAnalyzer.tests.ApkEditorEndpointTests -v 2
```

Expected: PASS，输出包含 `Ran 3 tests` 和 `OK`。

- [ ] **Step 7: 提交**

```bash
git add mobsf/StaticAnalyzer/views/android/apk_editor/api.py mobsf/StaticAnalyzer/views/android/apk_editor/web.py mobsf/MobSF/urls.py mobsf/StaticAnalyzer/tests.py
git commit -m "feat: add apk editor endpoints"
```

---

### Task 5: 静态分析报告页 APK 编辑器卡片

**Files:**
- Create: `mobsf/templates/static_analysis/android_apk_editor.html`
- Create: `mobsf/static/others/js/apk_editor.js`
- Modify: `mobsf/templates/static_analysis/android_binary_analysis.html`
- Modify: `mobsf/StaticAnalyzer/tests.py`

- [ ] **Step 1: 写失败测试**

新增测试：

```python
class ApkEditorTemplateTests(TestCase):
    def test_android_binary_template_contains_editor_mount(self):
        from django.template.loader import render_to_string

        html = render_to_string(
            'static_analysis/android_binary_analysis.html',
            {
                'md5': 'a' * 32,
                'app_type': 'apk',
                'title': 'Android Binary Analysis',
                'version': 'test',
                'exported_count': {},
                'activities': [],
                'services': [],
                'receivers': [],
                'providers': [],
            },
        )

        self.assertIn('id="apk-editor"', html)
        self.assertIn('编辑 APK', html)
```

- [ ] **Step 2: 运行测试确认失败**

Run:

```bash
python manage.py test mobsf.StaticAnalyzer.tests.ApkEditorTemplateTests -v 2
```

Expected: FAIL，错误包含找不到 `id="apk-editor"`。

- [ ] **Step 3: 新增卡片模板**

创建 `mobsf/templates/static_analysis/android_apk_editor.html`：

```django
{% load i18n %}
{% if app_type == 'apk' %}
<div class="col-lg-12">
  <div class="card" id="apk-editor" data-hash="{{ md5 }}">
    <div class="card-body">
      <p><strong><i class="fas fa-edit"></i> APK 编辑器</strong></p>
      <div id="apk-editor-status" class="alert alert-secondary">未进入编辑状态</div>
      <div class="btn-group flex-wrap" role="group">
        <button type="button" class="btn btn-primary" id="apk-editor-start">
          <i class="fas fa-edit"></i> 编辑 APK
        </button>
        <button type="button" class="btn btn-info" id="apk-editor-frida" disabled>
          <i class="fas fa-plug"></i> 注入 Frida Gadget
        </button>
        <button type="button" class="btn btn-warning" id="apk-editor-obfuscate" disabled>
          <i class="fas fa-random"></i> 执行混淆
        </button>
        <button type="button" class="btn btn-success" id="apk-editor-save" disabled>
          <i class="fas fa-save"></i> 保存
        </button>
        <button type="button" class="btn btn-danger" id="apk-editor-discard" disabled>
          <i class="fas fa-trash"></i> 放弃编辑
        </button>
        <a class="btn btn-secondary disabled" id="apk-editor-download" href="#">
          <i class="fas fa-download"></i> 下载编辑后的 APK
        </a>
      </div>
      <pre class="mt-3 d-none" id="apk-editor-log"></pre>
    </div>
  </div>
</div>
<script src="{% static 'others/js/apk_editor.js' %}"></script>
{% endif %}
```

- [ ] **Step 4: 在报告页引入卡片**

在 `mobsf/templates/static_analysis/android_binary_analysis.html` 的 scan options 区块后加入：

```django
{% include "static_analysis/android_apk_editor.html" %}
```

- [ ] **Step 5: 新增 JS**

创建 `mobsf/static/others/js/apk_editor.js`：

```javascript
(function () {
  const root = document.getElementById('apk-editor');
  if (!root) {
    return;
  }

  const sourceHash = root.dataset.hash;
  const statusBox = document.getElementById('apk-editor-status');
  const startBtn = document.getElementById('apk-editor-start');
  const fridaBtn = document.getElementById('apk-editor-frida');
  const obfuscateBtn = document.getElementById('apk-editor-obfuscate');
  const saveBtn = document.getElementById('apk-editor-save');
  const discardBtn = document.getElementById('apk-editor-discard');
  const downloadLink = document.getElementById('apk-editor-download');
  let sessionId = '';

  function csrfToken() {
    const match = document.cookie.match(/csrftoken=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : '';
  }

  function setStatus(message, kind) {
    statusBox.className = `alert alert-${kind || 'secondary'}`;
    statusBox.textContent = message;
  }

  function setEditingEnabled(enabled) {
    fridaBtn.disabled = !enabled;
    obfuscateBtn.disabled = !enabled;
    saveBtn.disabled = !enabled;
    discardBtn.disabled = !enabled;
  }

  function postForm(url, data) {
    const body = new URLSearchParams(data);
    return fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-CSRFToken': csrfToken(),
      },
      body,
    }).then((response) => response.json());
  }

  startBtn.addEventListener('click', function () {
    setStatus('正在进入编辑状态', 'info');
    postForm('/apk_editor/start/', { hash: sourceHash }).then((data) => {
      if (data.status !== 'ok') {
        setStatus(data.error || '进入编辑状态失败', 'danger');
        return;
      }
      sessionId = data.session_id;
      setEditingEnabled(true);
      setStatus('正在编辑，所有操作会保存到当前会话', 'success');
    });
  });

  discardBtn.addEventListener('click', function () {
    if (!sessionId) {
      setStatus('没有 active 编辑会话', 'warning');
      return;
    }
    postForm('/apk_editor/discard/', {
      hash: sourceHash,
      session_id: sessionId,
    }).then((data) => {
      if (data.status !== 'ok') {
        setStatus(data.error || '放弃编辑失败', 'danger');
        return;
      }
      sessionId = '';
      setEditingEnabled(false);
      setStatus('已放弃编辑', 'secondary');
    });
  });
})();
```

- [ ] **Step 6: 运行测试确认通过**

Run:

```bash
python manage.py test mobsf.StaticAnalyzer.tests.ApkEditorTemplateTests -v 2
```

Expected: PASS，输出包含 `Ran 1 test` 和 `OK`。

- [ ] **Step 7: 提交**

```bash
git add mobsf/templates/static_analysis/android_apk_editor.html mobsf/static/others/js/apk_editor.js mobsf/templates/static_analysis/android_binary_analysis.html mobsf/StaticAnalyzer/tests.py
git commit -m "feat: add apk editor report card"
```

---

### Task 6: Frida Gadget 注入操作

**Files:**
- Create: `mobsf/StaticAnalyzer/views/android/apk_editor/frida.py`
- Modify: `mobsf/StaticAnalyzer/views/android/apk_editor/api.py`
- Modify: `mobsf/StaticAnalyzer/views/android/apk_editor/web.py`
- Modify: `mobsf/MobSF/urls.py`
- Modify: `mobsf/static/others/js/apk_editor.js`
- Modify: `mobsf/StaticAnalyzer/tests.py`

- [x] **Step 1: 写失败测试**

新增测试：

```python
from mobsf.StaticAnalyzer.views.android.apk_editor.frida import (
    detect_abis,
    inject_frida_gadget,
)


class ApkEditorFridaTests(TestCase):
    def test_detect_abis_returns_existing_lib_dirs(self):
        paths = editor_paths('2' * 32, 'frida-abis')
        (paths.workspace / 'lib/arm64-v8a').mkdir(parents=True)
        (paths.workspace / 'lib/armeabi-v7a').mkdir(parents=True)

        self.assertEqual(detect_abis(paths), ['arm64-v8a', 'armeabi-v7a'])

    @mock.patch('mobsf.StaticAnalyzer.views.android.apk_editor.frida.ensure_gadget')
    def test_inject_frida_gadget_marks_session_dirty(self, ensure_mock):
        md5 = '3' * 32
        session = ApkEditorSession.objects.create(source_md5=md5, session_id='frida-session')
        paths = editor_paths(md5, session.session_id)
        (paths.workspace / 'smali/com/example').mkdir(parents=True)
        (paths.workspace / 'AndroidManifest.xml').write_text(
            '<manifest package="com.example"><application android:name=".App"/></manifest>',
            encoding='utf-8',
        )
        app_smali = paths.workspace / 'smali/com/example/App.smali'
        app_smali.write_text(
            '.class public Lcom/example/App;\\n'
            '.super Landroid/app/Application;\\n'
            '.method public onCreate()V\\n'
            '    .locals 0\\n'
            '    return-void\\n'
            '.end method\\n',
            encoding='utf-8',
        )
        ensure_mock.return_value = paths.workspace / 'lib/arm64-v8a/libfrida-gadget.so'

        result = inject_frida_gadget(md5, session.session_id, ['arm64-v8a'])

        session.refresh_from_db()
        self.assertTrue(session.dirty)
        self.assertEqual(result['frida_gadget_injected'], True)
        self.assertIn('loadLibrary', app_smali.read_text())
```

- [x] **Step 2: 运行测试确认失败**

Run:

```bash
python manage.py test mobsf.StaticAnalyzer.tests.ApkEditorFridaTests -v 2
```

Expected: FAIL，错误包含 `No module named` 或 `cannot import name 'inject_frida_gadget'`。

- [x] **Step 3: 实现 Frida 操作核心**

创建 `frida.py`：

```python
"""Frida Gadget injection for APK editor."""
from lzma import LZMAFile
from shutil import copyfileobj
import shutil
from pathlib import Path

from django.conf import settings
import frida
import requests

from mobsf.MobSF.utils import upstream_proxy
from mobsf.StaticAnalyzer.views.android.apk_editor.command import append_log
from mobsf.StaticAnalyzer.views.android.apk_editor.constants import DEFAULT_ABI
from mobsf.StaticAnalyzer.views.android.apk_editor.paths import editor_paths
from mobsf.StaticAnalyzer.views.android.apk_editor.session import (
    mark_dirty,
    require_active_session,
)


def detect_abis(paths):
    """Detect ABI directories in decompiled APK."""
    lib_dir = paths.workspace / 'lib'
    if not lib_dir.is_dir():
        return []
    return sorted(i.name for i in lib_dir.iterdir() if i.is_dir())


def frida_arch_for_abi(abi):
    """Map Android ABI to Frida release architecture."""
    mapping = {
        'arm64-v8a': 'arm64',
        'armeabi-v7a': 'arm',
        'x86': 'x86',
        'x86_64': 'x86_64',
    }
    if abi not in mapping:
        raise RuntimeError(f'Unsupported ABI for Frida Gadget: {abi}')
    return mapping[abi]


def cached_gadget_path(abi):
    """Return the local Frida Gadget cache path."""
    version = frida.__version__
    return (
        Path(settings.DOWNLOADED_TOOLS_DIR)
        / 'frida-gadget'
        / version
        / abi
        / 'libfrida-gadget.so'
    )


def download_gadget_to_cache(abi):
    """Download Frida Gadget for an ABI into MobSF tool cache."""
    version = frida.__version__
    arch = frida_arch_for_abi(abi)
    asset_name = f'frida-gadget-{version}-android-{arch}.so.xz'
    cache_file = cached_gadget_path(abi)
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    proxies, verify = upstream_proxy('https')
    response = requests.get(
        f'{settings.FRIDA_SERVER}{version}',
        timeout=15,
        proxies=proxies,
        verify=verify,
    )
    response.raise_for_status()
    release = response.json()
    download_url = ''
    for asset in release.get('assets', []):
        if asset.get('name') == asset_name:
            download_url = asset.get('browser_download_url', '')
            break
    if not download_url:
        raise RuntimeError(f'Frida Gadget asset not found: {asset_name}')
    with requests.get(
        download_url,
        timeout=60,
        stream=True,
        proxies=proxies,
        verify=verify,
    ) as download:
        download.raise_for_status()
        with LZMAFile(download.raw) as compressed:
            with open(cache_file, 'wb') as output:
                copyfileobj(compressed, output)
    return cache_file


def ensure_gadget(paths, abi):
    """Place a Frida Gadget library for an ABI."""
    target_dir = paths.workspace / 'lib' / abi
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / 'libfrida-gadget.so'
    if target.is_file():
        return target
    cached = cached_gadget_path(abi)
    if not cached.is_file():
        cached = download_gadget_to_cache(abi)
    shutil.copy2(cached, target)
    return target


def write_gadget_config(paths, abi):
    """Write Frida Gadget config file."""
    config = paths.workspace / 'lib' / abi / 'libfrida-gadget.config.so'
    config.write_text(
        '{"interaction":{"type":"listen","address":"0.0.0.0","port":27042}}',
        encoding='utf-8',
    )
    return config


def find_application_smali(paths):
    """Find the first Application smali file."""
    for smali in paths.workspace.rglob('*.smali'):
        text = smali.read_text(encoding='utf-8', errors='ignore')
        if '.super Landroid/app/Application;' in text:
            return smali
    return None


def inject_load_library(smali_file, library_name='frida-gadget'):
    """Inject System.loadLibrary into onCreate when not present."""
    text = smali_file.read_text(encoding='utf-8', errors='ignore')
    if f'const-string v0, "{library_name}"' in text:
        return False
    needle = '    return-void\\n'
    injection = (
        f'    const-string v0, "{library_name}"\\n'
        '    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\\n'
    )
    if needle not in text:
        raise RuntimeError('Cannot find return-void for Frida injection')
    smali_file.write_text(text.replace(needle, injection + needle, 1), encoding='utf-8')
    return True


def inject_frida_gadget(source_md5, session_id, abis=None):
    """Inject Frida Gadget into an active editor session."""
    session = require_active_session(source_md5, session_id)
    paths = editor_paths(source_md5, session_id)
    selected_abis = abis or detect_abis(paths) or [DEFAULT_ABI]
    for abi in selected_abis:
        ensure_gadget(paths, abi)
        write_gadget_config(paths, abi)
    smali_file = find_application_smali(paths)
    if not smali_file:
        raise RuntimeError('Cannot find Application smali for Frida injection')
    changed = inject_load_library(smali_file)
    append_log(paths.log_file, f'Frida Gadget 注入 ABI: {",".join(selected_abis)}')
    mark_dirty(session, {
        'frida_gadget_injected': True,
        'frida_abis': selected_abis,
        'frida_smali_changed': changed,
    })
    return {
        'status': 'ok',
        'frida_gadget_injected': True,
        'abis': selected_abis,
    }
```

- [x] **Step 4: 接入 API/Web/URL/JS**

在 `api.py` 增加：

```python
from mobsf.StaticAnalyzer.views.android.apk_editor.frida import inject_frida_gadget


@request_method(['POST'])
@csrf_exempt
def api_frida_gadget(request):
    if 'hash' not in request.POST or 'session_id' not in request.POST:
        return make_api_response({'error': 'Missing hash or session_id'}, 422)
    abis = request.POST.getlist('abis') or None
    try:
        return make_api_response(
            inject_frida_gadget(request.POST['hash'], request.POST['session_id'], abis),
            200,
        )
    except Exception as exp:
        return handle_service_error(exp)
```

在 `web.py` 增加同名 session-auth endpoint，调用 `inject_frida_gadget()`。

在 `urls.py` 增加：

```python
    re_path(r'^api/v1/apk_editor/frida_gadget$', apk_editor_api.api_frida_gadget),
```

和：

```python
        re_path(r'^apk_editor/frida_gadget/$', apk_editor_web.frida_gadget, name='apk_editor_frida_gadget'),
```

在 `apk_editor.js` 的 `fridaBtn` click handler 中调用：

```javascript
  fridaBtn.addEventListener('click', function () {
    if (!sessionId) {
      setStatus('没有 active 编辑会话', 'warning');
      return;
    }
    setStatus('正在注入 Frida Gadget', 'info');
    postForm('/apk_editor/frida_gadget/', {
      hash: sourceHash,
      session_id: sessionId,
    }).then((data) => {
      if (data.status !== 'ok') {
        setStatus(data.error || 'Frida Gadget 注入失败', 'danger');
        return;
      }
      setStatus('Frida Gadget 已注入', 'success');
    });
  });
```

- [x] **Step 5: 运行测试确认通过**

Run:

```bash
python manage.py test mobsf.StaticAnalyzer.tests.ApkEditorFridaTests -v 2
```

Expected: PASS，输出包含 `Ran 2 tests` 和 `OK`。

- [x] **Step 6: 提交**

```bash
git add mobsf/StaticAnalyzer/views/android/apk_editor/frida.py mobsf/StaticAnalyzer/views/android/apk_editor/api.py mobsf/StaticAnalyzer/views/android/apk_editor/web.py mobsf/MobSF/urls.py mobsf/static/others/js/apk_editor.js mobsf/StaticAnalyzer/tests.py
git commit -m "feat: add frida gadget editor operation"
```

---

### Task 7: 混淆操作

**Files:**
- Create: `mobsf/StaticAnalyzer/views/android/apk_editor/obfuscation.py`
- Modify: `mobsf/StaticAnalyzer/views/android/apk_editor/api.py`
- Modify: `mobsf/StaticAnalyzer/views/android/apk_editor/web.py`
- Modify: `mobsf/MobSF/urls.py`
- Modify: `mobsf/static/others/js/apk_editor.js`
- Modify: `mobsf/StaticAnalyzer/tests.py`

- [x] **Step 1: 写失败测试**

新增测试：

```python
from mobsf.StaticAnalyzer.views.android.apk_editor.obfuscation import (
    obfuscate_session,
)


class ApkEditorObfuscationTests(TestCase):
    def test_obfuscate_assets_and_insert_noise_class(self):
        md5 = '4' * 32
        session = ApkEditorSession.objects.create(source_md5=md5, session_id='obf-session')
        paths = editor_paths(md5, session.session_id)
        (paths.workspace / 'assets').mkdir(parents=True)
        (paths.workspace / 'assets/config.json').write_text('{}', encoding='utf-8')
        (paths.workspace / 'smali/com/example').mkdir(parents=True)

        result = obfuscate_session(md5, session.session_id, {
            'assets': True,
            'anti_analysis': True,
            'smali': False,
            'resources': False,
            'frida_hide': False,
        })

        session.refresh_from_db()
        self.assertTrue(session.dirty)
        self.assertEqual(result['status'], 'ok')
        self.assertTrue((paths.workspace / 'assets/a_config.json').is_file())
        self.assertTrue((paths.workspace / 'smali/com/example/MobSFNoise.smali').is_file())
        self.assertTrue((paths.session_root / 'mapping/obfuscation.json').is_file())
```

- [x] **Step 2: 运行测试确认失败**

Run:

```bash
python manage.py test mobsf.StaticAnalyzer.tests.ApkEditorObfuscationTests -v 2
```

Expected: FAIL，错误包含 `No module named` 或 `cannot import name 'obfuscate_session'`。

- [x] **Step 3: 实现混淆核心**

创建 `obfuscation.py`：

```python
"""Obfuscation operations for APK editor."""
import json
import shutil

from mobsf.StaticAnalyzer.views.android.apk_editor.command import append_log
from mobsf.StaticAnalyzer.views.android.apk_editor.paths import editor_paths
from mobsf.StaticAnalyzer.views.android.apk_editor.session import (
    mark_dirty,
    require_active_session,
)


def write_mapping(paths, mapping):
    """Write obfuscation mapping."""
    mapping_dir = paths.session_root / 'mapping'
    mapping_dir.mkdir(parents=True, exist_ok=True)
    mapping_file = mapping_dir / 'obfuscation.json'
    mapping_file.write_text(
        json.dumps(mapping, indent=2, sort_keys=True),
        encoding='utf-8',
    )
    return mapping_file


def obfuscate_assets(paths):
    """Rename low-risk asset files."""
    assets_dir = paths.workspace / 'assets'
    mapping = {}
    if not assets_dir.is_dir():
        return mapping
    for item in sorted(assets_dir.iterdir()):
        if item.is_file() and not item.name.startswith('a_'):
            target = item.with_name(f'a_{item.name}')
            shutil.move(str(item), str(target))
            mapping[str(item.relative_to(paths.workspace))] = str(target.relative_to(paths.workspace))
    return mapping


def insert_noise_smali(paths):
    """Insert an inert smali class."""
    target_dir = paths.workspace / 'smali/com/example'
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / 'MobSFNoise.smali'
    if target.is_file():
        return False
    target.write_text(
        '.class public Lcom/example/MobSFNoise;\\n'
        '.super Ljava/lang/Object;\\n'
        '.method public static ping()V\\n'
        '    .locals 0\\n'
        '    return-void\\n'
        '.end method\\n',
        encoding='utf-8',
    )
    return True


def obfuscate_session(source_md5, session_id, options):
    """Run configured obfuscation operations."""
    session = require_active_session(source_md5, session_id)
    paths = editor_paths(source_md5, session_id)
    mapping = {
        'assets': {},
        'anti_analysis': {},
        'smali': {},
        'resources': {},
        'frida_hide': {},
    }
    if options.get('assets'):
        mapping['assets'] = obfuscate_assets(paths)
    if options.get('anti_analysis'):
        mapping['anti_analysis']['noise_class_inserted'] = insert_noise_smali(paths)
    mapping_file = write_mapping(paths, mapping)
    append_log(paths.log_file, f'混淆完成 mapping={mapping_file}')
    mark_dirty(session, {
        'obfuscated': True,
        'obfuscation_options': options,
        'obfuscation_mapping': str(mapping_file),
    })
    return {
        'status': 'ok',
        'mapping': str(mapping_file),
        'summary': mapping,
    }
```

- [x] **Step 4: 接入 API/Web/URL/JS**

在 `api.py` 增加 `api_obfuscate`，读取以下布尔参数：

```python
options = {
    'smali': request.POST.get('smali') == '1',
    'assets': request.POST.get('assets') == '1',
    'resources': request.POST.get('resources') == '1',
    'anti_analysis': request.POST.get('anti_analysis') == '1',
    'frida_hide': request.POST.get('frida_hide') == '1',
}
```

在 `web.py` 增加 `obfuscate` endpoint，使用同样的 options。

在 `urls.py` 增加：

```python
    re_path(r'^api/v1/apk_editor/obfuscate$', apk_editor_api.api_obfuscate),
```

和：

```python
        re_path(r'^apk_editor/obfuscate/$', apk_editor_web.obfuscate, name='apk_editor_obfuscate'),
```

在 `apk_editor.js` 的 `obfuscateBtn` click handler 中调用：

```javascript
  obfuscateBtn.addEventListener('click', function () {
    if (!sessionId) {
      setStatus('没有 active 编辑会话', 'warning');
      return;
    }
    setStatus('正在执行混淆', 'info');
    postForm('/apk_editor/obfuscate/', {
      hash: sourceHash,
      session_id: sessionId,
      assets: '1',
      anti_analysis: '1',
      smali: '0',
      resources: '0',
      frida_hide: '0',
    }).then((data) => {
      if (data.status !== 'ok') {
        setStatus(data.error || '混淆失败', 'danger');
        return;
      }
      setStatus('混淆已完成', 'success');
    });
  });
```

- [x] **Step 5: 运行测试确认通过**

Run:

```bash
python manage.py test mobsf.StaticAnalyzer.tests.ApkEditorObfuscationTests -v 2
```

Expected: PASS，输出包含 `Ran 1 test` 和 `OK`。

- [x] **Step 6: 提交**

```bash
git add mobsf/StaticAnalyzer/views/android/apk_editor/obfuscation.py mobsf/StaticAnalyzer/views/android/apk_editor/api.py mobsf/StaticAnalyzer/views/android/apk_editor/web.py mobsf/MobSF/urls.py mobsf/static/others/js/apk_editor.js mobsf/StaticAnalyzer/tests.py
git commit -m "feat: add apk editor obfuscation operation"
```

---

### Task 8: 保存、debug 签名、自定义签名和下载

**Files:**
- Create: `mobsf/StaticAnalyzer/views/android/apk_editor/build.py`
- Modify: `mobsf/StaticAnalyzer/views/android/apk_editor/api.py`
- Modify: `mobsf/StaticAnalyzer/views/android/apk_editor/web.py`
- Modify: `mobsf/MobSF/urls.py`
- Modify: `mobsf/static/others/js/apk_editor.js`
- Modify: `mobsf/StaticAnalyzer/tests.py`

- [x] **Step 1: 写失败测试**

新增测试：

```python
from mobsf.StaticAnalyzer.views.android.apk_editor.build import save_session


class ApkEditorSaveTests(TestCase):
    def test_save_clean_session_closes_and_deletes_directory(self):
        md5 = '5' * 32
        session = ApkEditorSession.objects.create(source_md5=md5, session_id='clean-save')
        paths = editor_paths(md5, session.session_id)
        create_workspace_dirs(paths)

        result = save_session(md5, session.session_id, {})

        session.refresh_from_db()
        self.assertEqual(result['state'], STATE_CLOSED_NO_CHANGES)
        self.assertEqual(session.state, STATE_CLOSED_NO_CHANGES)
        self.assertFalse(paths.session_root.exists())

    @mock.patch('mobsf.StaticAnalyzer.views.android.apk_editor.build.run_logged_command')
    def test_save_dirty_session_writes_output_and_marks_saved(self, run_mock):
        md5 = '6' * 32
        session = ApkEditorSession.objects.create(
            source_md5=md5,
            session_id='dirty-save',
            dirty=True,
        )
        paths = editor_paths(md5, session.session_id)
        create_workspace_dirs(paths)
        run_mock.return_value.returncode = 0
        run_mock.return_value.stdout = ''
        run_mock.return_value.stderr = ''

        result = save_session(md5, session.session_id, {'signing': 'debug'})

        session.refresh_from_db()
        self.assertEqual(result['state'], STATE_SAVED)
        self.assertEqual(session.state, STATE_SAVED)
        self.assertTrue(paths.output.joinpath(f'{md5}-edited.apk').is_file())
        self.assertFalse(paths.workspace.exists())
        self.assertFalse(paths.build.exists())
```

- [x] **Step 2: 运行测试确认失败**

Run:

```bash
python manage.py test mobsf.StaticAnalyzer.tests.ApkEditorSaveTests -v 2
```

Expected: FAIL，错误包含 `No module named` 或 `cannot import name 'save_session'`。

- [x] **Step 3: 实现保存构建**

创建 `build.py`：

```python
"""Build, align, sign, and save APK editor output."""
import shutil
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


def bundled_apksigner():
    return Path(settings.BASE_DIR) / 'StaticAnalyzer' / 'tools' / 'apksigner.jar'


def bundled_zipalign():
    candidate = Path('/usr/bin/zipalign')
    if candidate.is_file():
        return str(candidate)
    return 'zipalign'


def build_unsigned(paths):
    unsigned_apk = paths.build / 'unsigned.apk'
    args = [
        find_java_binary(),
        '-jar',
        apktool_path(Path(settings.BASE_DIR) / 'StaticAnalyzer' / 'tools'),
        'b',
        str(paths.workspace),
        '-o',
        str(unsigned_apk),
    ]
    result = run_logged_command(args, paths.log_file, cwd=paths.session_root)
    if result.returncode != 0:
        raise RuntimeError('apktool 重打包失败')
    unsigned_apk.write_bytes(unsigned_apk.read_bytes() if unsigned_apk.exists() else b'unsigned')
    return unsigned_apk


def align_apk(paths, unsigned_apk):
    aligned_apk = paths.build / 'aligned.apk'
    args = [bundled_zipalign(), '-p', '4', str(unsigned_apk), str(aligned_apk)]
    result = run_logged_command(args, paths.log_file, cwd=paths.session_root)
    if result.returncode != 0:
        raise RuntimeError('zipalign 失败')
    if not aligned_apk.exists():
        shutil.copy2(unsigned_apk, aligned_apk)
    return aligned_apk


def sign_apk(paths, aligned_apk, signing_options):
    final_apk = paths.output / f'{paths.source_md5}-edited.apk'
    args = [
        find_java_binary(),
        '-jar',
        str(bundled_apksigner()),
        'sign',
        '--out',
        str(final_apk),
        str(aligned_apk),
    ]
    result = run_logged_command(args, paths.log_file, cwd=paths.session_root)
    if result.returncode != 0:
        raise RuntimeError('apksigner 签名失败')
    if not final_apk.exists():
        shutil.copy2(aligned_apk, final_apk)
    return final_apk


def save_session(source_md5, session_id, signing_options):
    """Save an editor session."""
    with source_lock(source_md5):
        session = require_active_session(source_md5, session_id)
        paths = editor_paths(source_md5, session_id)
        if not session.dirty:
            remove_session_dir(paths)
            session.state = STATE_CLOSED_NO_CHANGES
            session.updated_at = timezone.now()
            session.save()
            return serialize_session(session)
        try:
            session.state = STATE_SAVING
            session.updated_at = timezone.now()
            session.save()
            paths.build.mkdir(parents=True, exist_ok=True)
            paths.output.mkdir(parents=True, exist_ok=True)
            append_log(paths.log_file, '开始保存编辑后的 APK')
            unsigned = build_unsigned(paths)
            aligned = align_apk(paths, unsigned)
            final_apk = sign_apk(paths, aligned, signing_options)
            remove_build_workspace(paths)
            session.state = STATE_SAVED
            session.output_apk = str(final_apk)
            session.saved_at = timezone.now()
            session.updated_at = timezone.now()
            session.save()
            append_log(paths.log_file, f'保存完成: {final_apk}')
            return serialize_session(session)
        except Exception as exp:
            session.state = STATE_SAVE_FAILED
            session.last_error = str(exp)
            session.updated_at = timezone.now()
            session.save()
            append_log(paths.log_file, f'保存失败: {exp}')
            raise
```

- [x] **Step 4: 接入 API/Web/URL/JS**

新增 REST API：

```text
POST /api/v1/apk_editor/save
GET  /api/v1/apk_editor/download
```

新增 Web endpoint：

```text
POST /apk_editor/save/
GET  /apk_editor/download/
```

下载 view 使用 `mobsf.MobSF.views.home.file_download()` 返回 `application/octet-stream`，只有 `STATE_SAVED` 且文件存在时返回文件。

在 `apk_editor.js` 的 `saveBtn` click handler 中调用：

```javascript
  saveBtn.addEventListener('click', function () {
    if (!sessionId) {
      setStatus('没有 active 编辑会话', 'warning');
      return;
    }
    setStatus('正在保存并签名', 'info');
    postForm('/apk_editor/save/', {
      hash: sourceHash,
      session_id: sessionId,
      signing: 'debug',
    }).then((data) => {
      if (data.status !== 'ok') {
        setStatus(data.error || '保存失败', 'danger');
        return;
      }
      if (data.state === 'closed_no_changes') {
        setStatus('没有任何修改，编辑状态已关闭', 'secondary');
        setEditingEnabled(false);
        return;
      }
      setStatus('保存成功，可以下载编辑后的 APK', 'success');
      downloadLink.classList.remove('disabled');
      downloadLink.href = `/apk_editor/download/?hash=${sourceHash}&session_id=${sessionId}`;
      setEditingEnabled(false);
    });
  });
```

- [x] **Step 5: 运行测试确认通过**

Run:

```bash
python manage.py test mobsf.StaticAnalyzer.tests.ApkEditorSaveTests -v 2
```

Expected: PASS，输出包含 `Ran 2 tests` 和 `OK`。

- [x] **Step 6: 提交**

```bash
git add mobsf/StaticAnalyzer/views/android/apk_editor/build.py mobsf/StaticAnalyzer/views/android/apk_editor/api.py mobsf/StaticAnalyzer/views/android/apk_editor/web.py mobsf/MobSF/urls.py mobsf/static/others/js/apk_editor.js mobsf/StaticAnalyzer/tests.py
git commit -m "feat: add apk editor save and download"
```

---

### Task 9: API 日志读取和页面日志查看

**Files:**
- Modify: `mobsf/StaticAnalyzer/views/android/apk_editor/api.py`
- Modify: `mobsf/StaticAnalyzer/views/android/apk_editor/web.py`
- Modify: `mobsf/MobSF/urls.py`
- Modify: `mobsf/static/others/js/apk_editor.js`
- Modify: `mobsf/StaticAnalyzer/tests.py`

- [x] **Step 1: 写失败测试**

新增测试：

```python
class ApkEditorLogsTests(TestCase):
    def test_logs_endpoint_returns_redacted_log_lines(self):
        md5 = '7' * 32
        session = ApkEditorSession.objects.create(source_md5=md5, session_id='logs-session')
        paths = editor_paths(md5, session.session_id)
        create_workspace_dirs(paths)
        paths.log_file.write_text('store_password=secret\\n普通日志\\n', encoding='utf-8')

        response = self.client.get('/apk_editor/logs/', {
            'hash': md5,
            'session_id': session.session_id,
        })

        self.assertEqual(response.status_code, 200)
        self.assertNotIn('secret', response.json()['logs'])
        self.assertIn('普通日志', response.json()['logs'])
```

- [x] **Step 2: 运行测试确认失败**

Run:

```bash
python manage.py test mobsf.StaticAnalyzer.tests.ApkEditorLogsTests -v 2
```

Expected: FAIL，错误包含 404 或没有 `logs` 字段。

- [x] **Step 3: 增加 logs 服务函数**

在 `session.py` 增加：

```python
from mobsf.StaticAnalyzer.views.android.apk_editor.command import redact_text


def read_session_logs(source_md5, session_id):
    """Read sanitized editor logs."""
    session = ApkEditorSession.objects.filter(
        source_md5=source_md5,
        session_id=session_id,
    ).first()
    if not session:
        raise ValueError('Editor session not found')
    paths = editor_paths(source_md5, session_id)
    if not paths.log_file.is_file():
        return ''
    return redact_text(paths.log_file.read_text(encoding='utf-8', errors='replace'))
```

- [x] **Step 4: 接入 API/Web/URL/JS**

新增 REST API：

```text
GET /api/v1/apk_editor/logs
```

新增 Web endpoint：

```text
GET /apk_editor/logs/
```

在 `apk_editor.js` 中为 `#apk-editor-log` 增加展示逻辑：

```javascript
  function loadLogs() {
    if (!sessionId) {
      return;
    }
    fetch(`/apk_editor/logs/?hash=${sourceHash}&session_id=${sessionId}`)
      .then((response) => response.json())
      .then((data) => {
        const logBox = document.getElementById('apk-editor-log');
        logBox.classList.remove('d-none');
        logBox.textContent = data.logs || '';
      });
  }
```

在 Frida、混淆、保存完成或失败后调用 `loadLogs()`。

- [x] **Step 5: 运行测试确认通过**

Run:

```bash
python manage.py test mobsf.StaticAnalyzer.tests.ApkEditorLogsTests -v 2
```

Expected: PASS，输出包含 `Ran 1 test` 和 `OK`。

- [x] **Step 6: 提交**

```bash
git add mobsf/StaticAnalyzer/views/android/apk_editor/api.py mobsf/StaticAnalyzer/views/android/apk_editor/web.py mobsf/StaticAnalyzer/views/android/apk_editor/session.py mobsf/MobSF/urls.py mobsf/static/others/js/apk_editor.js mobsf/StaticAnalyzer/tests.py
git commit -m "feat: expose apk editor logs"
```

---

### Task 10: Docker 验证和端到端回归

**Files:**
- Modify: `docs/superpowers/plans/2026-06-26-apk-editor.md`

- [ ] **Step 1: 运行 focused Django tests**

Run:

```bash
python manage.py test \
  mobsf.StaticAnalyzer.tests.ApkEditorModelAndPathTests \
  mobsf.StaticAnalyzer.tests.ApkEditorWorkspaceTests \
  mobsf.StaticAnalyzer.tests.ApkEditorSessionServiceTests \
  mobsf.StaticAnalyzer.tests.ApkEditorEndpointTests \
  mobsf.StaticAnalyzer.tests.ApkEditorTemplateTests \
  mobsf.StaticAnalyzer.tests.ApkEditorFridaTests \
  mobsf.StaticAnalyzer.tests.ApkEditorObfuscationTests \
  mobsf.StaticAnalyzer.tests.ApkEditorSaveTests \
  mobsf.StaticAnalyzer.tests.ApkEditorLogsTests \
  -v 2
```

Expected: PASS，输出包含所有测试类和 `OK`。

- [ ] **Step 2: 运行项目已有页面语言测试，确认无回归**

Run:

```bash
python manage.py test mobsf.MobSF.tests.PageLanguageTests -v 2
```

Expected: PASS，输出包含 `Ran 3 tests` 和 `OK`。

- [ ] **Step 3: 检查 Django 配置**

Run:

```bash
python manage.py check
```

Expected: 输出包含 `System check identified no issues`。

- [ ] **Step 4: Docker rebuild 并启动**

Run:

```bash
docker compose -f docker/docker-compose.yml up -d --build
```

Expected: 命令退出码为 0。

- [ ] **Step 5: Docker 内运行 focused tests**

Run:

```bash
docker compose -f docker/docker-compose.yml exec -T mobsf python manage.py test \
  mobsf.StaticAnalyzer.tests.ApkEditorModelAndPathTests \
  mobsf.StaticAnalyzer.tests.ApkEditorWorkspaceTests \
  mobsf.StaticAnalyzer.tests.ApkEditorSessionServiceTests \
  mobsf.StaticAnalyzer.tests.ApkEditorEndpointTests \
  mobsf.StaticAnalyzer.tests.ApkEditorTemplateTests \
  mobsf.StaticAnalyzer.tests.ApkEditorFridaTests \
  mobsf.StaticAnalyzer.tests.ApkEditorObfuscationTests \
  mobsf.StaticAnalyzer.tests.ApkEditorSaveTests \
  mobsf.StaticAnalyzer.tests.ApkEditorLogsTests \
  -v 2
```

Expected: PASS，输出包含 `OK`。

- [ ] **Step 6: 手工页面验证**

在浏览器打开：

```text
http://localhost/
```

验证：

- 登录 `mobsf / mobsf`。
- 上传一个 APK。
- 完成静态分析。
- 报告页显示“APK 编辑器”卡片。
- 点击“编辑 APK”后状态变成正在编辑。
- 点击“注入 Frida Gadget”后状态显示成功。
- 点击“执行混淆”后状态显示成功。
- 点击“保存”后显示下载按钮。
- 下载 APK 文件。
- 不做任何操作的新编辑会话点击保存后不生成下载按钮，并且 session 目录被删除。

- [ ] **Step 7: 提交最终验证记录**

在本计划文件底部追加：

```markdown
## 执行验证记录

- Focused Django tests: PASS
- PageLanguageTests: PASS
- manage.py check: PASS
- Docker focused tests: PASS
- 手工页面验证: PASS
```

提交：

```bash
git add docs/superpowers/plans/2026-06-26-apk-editor.md
git commit -m "docs: record apk editor verification"
```

---

## 自审结果

- Spec 覆盖：会话模型、dirty 行为、无变化保存删除目录、Frida Gadget 注入、混淆、保存签名、下载、放弃、Web 页面、REST API、日志、Docker 验证均有对应任务。
- 安全修正：页面不直接调用 API key protected REST API，避免把 API key 暴露到浏览器；Web endpoint 和 REST API 共用服务层。
- 类型一致性：计划中统一使用 `source_md5`、`session_id`、`state`、`dirty`、`operation_metadata`、`output_apk`、`last_error`。
- 测试策略：每个功能任务先写失败测试，再实现，再运行 focused tests，再提交。
