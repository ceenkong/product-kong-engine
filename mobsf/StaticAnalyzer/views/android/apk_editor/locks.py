import os
import re
import time
from contextlib import contextmanager
from pathlib import Path

from django.conf import settings


SOURCE_MD5_RE = re.compile(r'^[0-9a-fA-F]{32}$')


def _is_stale_lock(lock_file, timeout):
    now = time.time()
    try:
        created_at = float(lock_file.read_text(encoding='utf-8').strip())
    except (OSError, ValueError):
        try:
            created_at = lock_file.stat().st_mtime
        except OSError:
            return False
    return now - created_at > timeout


@contextmanager
def source_lock(source_md5, timeout=30, stale_after=3600):
    if not isinstance(source_md5, str) or not SOURCE_MD5_RE.fullmatch(
            source_md5):
        raise ValueError('source_md5 must be a 32 character hex string')

    lock_file = (
        Path(settings.UPLD_DIR)
        / source_md5
        / 'apk_editor'
        / '.editor.lock'
    )
    lock_file.parent.mkdir(parents=True, exist_ok=True)

    fd = None
    deadline = time.monotonic() + timeout
    while fd is None:
        try:
            new_fd = os.open(
                lock_file,
                os.O_CREAT | os.O_EXCL | os.O_RDWR,
            )
            try:
                os.write(new_fd, str(time.time()).encode('utf-8'))
            except Exception:
                os.close(new_fd)
                raise
            fd = new_fd
        except FileExistsError:
            if _is_stale_lock(lock_file, stale_after):
                try:
                    lock_file.unlink()
                    continue
                except FileNotFoundError:
                    continue
            if time.monotonic() >= deadline:
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
