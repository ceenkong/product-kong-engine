import re
import shutil
from lzma import LZMAFile
from pathlib import Path
from shutil import copyfileobj

from django.conf import settings
import frida
import requests

from mobsf.MobSF.utils import upstream_proxy
from mobsf.StaticAnalyzer.views.android.apk_editor.command import append_log
from mobsf.StaticAnalyzer.views.android.apk_editor.constants import DEFAULT_ABI
from mobsf.StaticAnalyzer.views.android.apk_editor.locks import source_lock
from mobsf.StaticAnalyzer.views.android.apk_editor.paths import editor_paths
from mobsf.StaticAnalyzer.views.android.apk_editor.session import (
    mark_dirty,
    require_active_session,
)


ABI_ARCH_MAP = {
    'arm64-v8a': 'arm64',
    'armeabi-v7a': 'arm',
    'x86': 'x86',
    'x86_64': 'x86_64',
}

ON_CREATE_RE = re.compile(
    (
        r'(?P<header>\.method[^\n]*\sonCreate\(\)V\n)'
        r'(?P<body>.*?)'
        r'(?P<end>\.end method)'
    ),
    re.DOTALL,
)
LOCALS_RE = re.compile(
    (
        r'(?m)^(?P<prefix>\s*)'
        r'\.(?P<kind>locals|registers)\s+'
        r'(?P<count>\d+)\s*$'
    ),
)


def detect_abis(paths):
    """Detect ABI directories in a decompiled APK workspace."""
    lib_dir = paths.workspace / 'lib'
    if not lib_dir.is_dir():
        return []
    return sorted(item.name for item in lib_dir.iterdir() if item.is_dir())


def frida_arch_for_abi(abi):
    """Map Android ABI to Frida release architecture."""
    if abi not in ABI_ARCH_MAP:
        raise RuntimeError(f'Unsupported ABI for Frida Gadget: {abi}')
    return ABI_ARCH_MAP[abi]


def cached_gadget_path(abi):
    """Return the local Frida Gadget cache path for an ABI."""
    frida_arch_for_abi(abi)
    return (
        Path(settings.DOWNLOADED_TOOLS_DIR)
        / 'frida-gadget'
        / frida.__version__
        / abi
        / 'libfrida-gadget.so'
    )


def download_gadget_to_cache(abi):
    """Download Frida Gadget for an ABI into the MobSF tool cache."""
    arch = frida_arch_for_abi(abi)
    asset_name = f'frida-gadget-{frida.__version__}-android-{arch}.so.xz'
    cache_file = cached_gadget_path(abi)
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    proxies, verify = upstream_proxy('https')

    response = requests.get(
        f'{settings.FRIDA_SERVER}{frida.__version__}',
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
            verify=verify) as download:
        download.raise_for_status()
        with LZMAFile(download.raw) as compressed:
            with cache_file.open('wb') as output:
                copyfileobj(compressed, output)

    return cache_file


def ensure_gadget(paths, abi):
    """Place a Frida Gadget shared library for an ABI in the workspace."""
    frida_arch_for_abi(abi)
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
    """Write Frida Gadget listen-mode config next to the ABI library."""
    frida_arch_for_abi(abi)
    config = paths.workspace / 'lib' / abi / 'libfrida-gadget.config.so'
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(
        (
            '{"interaction":{"type":"listen",'
            '"address":"0.0.0.0","port":27042}}'
        ),
        encoding='utf-8',
    )
    return config


def find_application_smali(paths):
    """Find the first smali class extending android.app.Application."""
    for smali_file in sorted(paths.workspace.rglob('*.smali')):
        text = smali_file.read_text(encoding='utf-8', errors='ignore')
        if '.super Landroid/app/Application;' in text:
            return smali_file
    return None


def _ensure_one_local_register(method_body):
    """Ensure v0 can be used inside the target method."""
    match = LOCALS_RE.search(method_body)
    if not match:
        return '    .locals 1\n' + method_body

    count = int(match.group('count'))
    minimum = 1
    if match.group('kind') == 'registers':
        minimum = 2
    if count < minimum:
        return (
            method_body[:match.start('count')]
            + str(minimum)
            + method_body[match.end('count'):]
        )
    return method_body


def _inject_into_on_create(text, library_name):
    match = ON_CREATE_RE.search(text)
    injection = (
        f'    const-string v0, "{library_name}"\n'
        '    invoke-static {v0}, '
        'Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n'
    )
    if not match:
        method = (
            '\n.method public onCreate()V\n'
            '    .locals 1\n'
            '    invoke-super {p0}, '
            'Landroid/app/Application;->onCreate()V\n'
            f'{injection}'
            '    return-void\n'
            '.end method\n'
        )
        return text.rstrip('\n') + method

    body = _ensure_one_local_register(match.group('body'))
    return_pos = body.find('    return-void\n')
    if return_pos == -1:
        raise RuntimeError('Cannot find return-void for Frida injection')

    body = body[:return_pos] + injection + body[return_pos:]
    return text[:match.start('body')] + body + text[match.end('body'):]


def inject_load_library(smali_file, library_name='frida-gadget'):
    """Inject System.loadLibrary into an Application smali file."""
    text = smali_file.read_text(encoding='utf-8', errors='ignore')
    if f'const-string v0, "{library_name}"' in text:
        return False

    smali_file.write_text(
        _inject_into_on_create(text, library_name),
        encoding='utf-8',
    )
    return True


def inject_frida_gadget(source_md5, session_id, abis=None):
    """Inject Frida Gadget into an active APK editor session."""
    with source_lock(source_md5):
        session = require_active_session(source_md5, session_id)
        paths = editor_paths(source_md5, session_id)
        selected_abis = abis or detect_abis(paths) or [DEFAULT_ABI]

        for abi in selected_abis:
            ensure_gadget(paths, abi)
            write_gadget_config(paths, abi)

        smali_file = find_application_smali(paths)
        if not smali_file:
            raise RuntimeError(
                'Cannot find Application smali for Frida injection')
        changed = inject_load_library(smali_file)

        append_log(
            paths.log_file,
            f'Frida Gadget 注入 ABI: {",".join(selected_abis)}',
        )
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
