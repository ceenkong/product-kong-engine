import shutil

from django.conf import settings

from mobsf.MobSF.utils import find_java_binary
from mobsf.StaticAnalyzer.views.android.apk_editor.command import (
    append_log,
    run_logged_command,
)


def create_workspace_dirs(paths):
    for directory in (
            paths.workspace,
            paths.build,
            paths.output,
            paths.logs):
        directory.mkdir(parents=True, exist_ok=True)


def remove_session_dir(paths):
    shutil.rmtree(paths.session_root, ignore_errors=True)


def remove_build_workspace(paths):
    shutil.rmtree(paths.workspace, ignore_errors=True)
    shutil.rmtree(paths.build, ignore_errors=True)


def apktool_path(tools_dir):
    configured_apktool = getattr(settings, 'APKTOOL_BINARY', '')
    if configured_apktool:
        return configured_apktool
    return str(tools_dir / 'apktool_2.10.0.jar')


def decompile_apk(paths, tools_dir):
    create_workspace_dirs(paths)
    append_log(paths.log_file, '开始 apktool 解包')

    result = run_logged_command(
        [
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
        ],
        paths.log_file,
        cwd=paths.session_root,
    )
    if result.returncode != 0:
        raise RuntimeError('apktool 解包失败')

    append_log(paths.log_file, 'apktool 解包完成')
