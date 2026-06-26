import json
import shutil

from mobsf.StaticAnalyzer.views.android.apk_editor.command import append_log
from mobsf.StaticAnalyzer.views.android.apk_editor.locks import source_lock
from mobsf.StaticAnalyzer.views.android.apk_editor.paths import editor_paths
from mobsf.StaticAnalyzer.views.android.apk_editor.session import (
    mark_dirty,
    require_active_session,
)


MAPPING_DIR = 'mapping'
MAPPING_FILE = 'obfuscation.json'


def write_mapping(paths, mapping):
    """Write an obfuscation mapping file in the editor session."""
    mapping_dir = paths.session_root / MAPPING_DIR
    mapping_dir.mkdir(parents=True, exist_ok=True)
    mapping_file = mapping_dir / MAPPING_FILE
    mapping_file.write_text(
        json.dumps(mapping, indent=2, sort_keys=True),
        encoding='utf-8',
    )
    return mapping_file


def obfuscate_assets(paths):
    """Rename low-risk top-level asset files and return old/new mapping."""
    assets_dir = paths.workspace / 'assets'
    mapping = {}
    if not assets_dir.is_dir():
        return mapping

    for item in sorted(assets_dir.iterdir()):
        if not item.is_file() or item.name.startswith('a_'):
            continue
        target = item.with_name(f'a_{item.name}')
        if target.exists():
            continue
        shutil.move(str(item), str(target))
        mapping[str(item.relative_to(paths.workspace))] = str(
            target.relative_to(paths.workspace))
    return mapping


def _smali_root(paths):
    if (paths.workspace / 'smali').is_dir():
        return paths.workspace / 'smali'
    for smali_dir in sorted(paths.workspace.glob('smali*')):
        if smali_dir.is_dir():
            return smali_dir
    return paths.workspace / 'smali'


def insert_noise_smali(paths):
    """Insert an inert smali class."""
    target_dir = _smali_root(paths) / 'com/example'
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / 'MobSFNoise.smali'
    if target.is_file():
        return False
    target.write_text(
        '.class public Lcom/example/MobSFNoise;\n'
        '.super Ljava/lang/Object;\n'
        '.method public static ping()V\n'
        '    .locals 0\n'
        '    return-void\n'
        '.end method\n',
        encoding='utf-8',
    )
    return True


def insert_resource_noise(paths):
    """Insert an unused values XML resource."""
    values_dir = paths.workspace / 'res/values'
    values_dir.mkdir(parents=True, exist_ok=True)
    target = values_dir / 'mobsf_obfuscation.xml'
    if target.is_file():
        return False
    target.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<resources>\n'
        '    <string name="mobsf_noise">mobsf</string>\n'
        '</resources>\n',
        encoding='utf-8',
    )
    return True


def empty_mapping():
    return {
        'assets': {},
        'anti_analysis': {},
        'smali': {},
        'resources': {},
        'frida_hide': {},
    }


def mapping_has_changes(mapping):
    return any((
        bool(mapping['assets']),
        bool(mapping['anti_analysis'].get('noise_class_inserted')),
        bool(mapping['smali'].get('noise_class_inserted')),
        bool(mapping['resources'].get('resource_inserted')),
    ))


def obfuscate_session(source_md5, session_id, options):
    """Run configured obfuscation operations for an active session."""
    with source_lock(source_md5):
        session = require_active_session(source_md5, session_id)
        paths = editor_paths(source_md5, session_id)
        mapping = empty_mapping()

        if options.get('assets'):
            mapping['assets'] = obfuscate_assets(paths)
        if options.get('anti_analysis'):
            mapping['anti_analysis']['noise_class_inserted'] = (
                insert_noise_smali(paths))
        if options.get('smali'):
            mapping['smali']['noise_class_inserted'] = (
                insert_noise_smali(paths))
        if options.get('resources'):
            mapping['resources']['resource_inserted'] = (
                insert_resource_noise(paths))
        if options.get('frida_hide'):
            mapping['frida_hide']['requested'] = True

        mapping_file = write_mapping(paths, mapping)
        changed = mapping_has_changes(mapping)
        if changed:
            append_log(paths.log_file, f'混淆完成 mapping={mapping_file}')
            mark_dirty(session, {
                'obfuscated': True,
                'obfuscation_options': options,
                'obfuscation_mapping': str(mapping_file),
            })
        else:
            append_log(paths.log_file, '混淆未产生文件变化')

        return {
            'status': 'ok',
            'changed': changed,
            'mapping': str(mapping_file),
            'summary': mapping,
        }
