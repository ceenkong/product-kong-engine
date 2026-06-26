STATE_ACTIVE = 'active'
STATE_SAVING = 'saving'
STATE_SAVED = 'saved'
STATE_SAVE_FAILED = 'save_failed'
STATE_CLOSED_NO_CHANGES = 'closed_no_changes'
STATE_DISCARDED = 'discarded'

ACTIVE_STATES = {
    STATE_ACTIVE,
    STATE_SAVE_FAILED,
}
CLOSED_STATES = {
    STATE_SAVED,
    STATE_CLOSED_NO_CHANGES,
    STATE_DISCARDED,
}

DEFAULT_ABI = 'arm64-v8a'

EDITOR_DIR = 'apk_editor'
WORKSPACE_DIR = 'workspace'
BUILD_DIR = 'build'
OUTPUT_DIR = 'output'
LOG_DIR = 'logs'
LOG_FILE = 'editor.log'

SECRET_KEYS = {
    'api_key',
    'apikey',
    'authorization',
    'key_password',
    'keystore_password',
    'password',
    'private_key',
    'secret',
    'secret_key',
    'signing_password',
    'store_password',
    'token',
}
