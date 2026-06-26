import re
import shlex
import subprocess
from dataclasses import dataclass

from mobsf.StaticAnalyzer.views.android.apk_editor.constants import SECRET_KEYS


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


SECRET_VALUE_RE = re.compile(
    (
        r'\b('
        + '|'.join(re.escape(key) for key in SECRET_KEYS)
        + r')\s*=\s*(?:"[^"]*"|\'[^\']*\'|[^\s]+)'
    ),
    re.IGNORECASE,
)


def redact_text(text):
    """Redact secret key=value pairs from logs."""
    if text is None:
        return ''

    def replace_secret(match):
        return f'{match.group(1)}=<redacted>'

    return SECRET_VALUE_RE.sub(replace_secret, str(text))


def append_log(log_file, message):
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open('a', encoding='utf-8') as log_handle:
        log_handle.write(f'{redact_text(message)}\n')


def run_logged_command(args, log_file, cwd=None, timeout=None):
    command_args = [str(arg) for arg in args]
    append_log(log_file, f'$ {shlex.join(command_args)}')
    completed = subprocess.run(
        command_args,
        cwd=cwd,
        timeout=timeout,
        capture_output=True,
        text=True,
        check=False,
    )
    stdout = completed.stdout or ''
    stderr = completed.stderr or ''

    if stdout:
        append_log(log_file, stdout.rstrip('\n'))
    if stderr:
        append_log(log_file, stderr.rstrip('\n'))

    return CommandResult(
        returncode=completed.returncode,
        stdout=stdout,
        stderr=stderr,
    )
