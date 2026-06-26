# APK Editor Design

## Goal

Add an APK editing workflow to MobSF that lets users put a selected APK into an
editing state, apply Frida Gadget injection and obfuscation operations, and then
save the result. Saving only rebuilds, aligns, signs, and exposes a new APK for
download when the editing session has changes. If no editing operation was
performed, saving closes the session and deletes the temporary workspace.

The generated APK is only offered for download. It is not automatically imported
back into MobSF and does not automatically trigger a new static scan.

## Scope

First version supports:

- One active edit session per source APK.
- Shared active session behavior across users and browser windows.
- Frida Gadget injection.
- Configurable obfuscation:
  - Smali/package/class/method obfuscation.
  - Resource and asset obfuscation.
  - Anti-analysis obfuscation.
- Save with debug signing by default.
- Save with custom keystore as an advanced option.
- Web UI, REST API, and editor logs.
- Download of the saved edited APK.
- Discarding an active session.

Out of scope for the first version:

- Automatic rescanning of the generated APK.
- Importing the generated APK into MobSF as a new scan.
- Full rollback or undo history.
- General-purpose file editing.
- Visual AndroidManifest editing.
- XAPK, APKS, AAB, IPA, or source ZIP editing.

## Session Model

The source APK is identified by its existing MobSF scan checksum:

```text
uploads/<source_md5>/<source_md5>.apk
```

The editor stores work under the source scan directory:

```text
uploads/<source_md5>/apk_editor/<session_id>/workspace/
uploads/<source_md5>/apk_editor/<session_id>/build/
uploads/<source_md5>/apk_editor/<session_id>/output/
uploads/<source_md5>/apk_editor/<session_id>/logs/editor.log
```

`source_md5` is the original uploaded APK's MD5. `session_id` is a unique
identifier for the editing draft, such as a timestamp plus short random suffix.
It is an internal identifier and does not need to be prominent in the UI.

Only one session per source APK can be active at the same time:

- If no active session exists, "Edit APK" creates a new session and decompiles
  the source APK into `workspace/` using apktool.
- If the initial decompile fails, the session must not become editable. The
  failure should be recorded, temporary files should be cleaned when safe, and
  the UI/API should return a clear start failure.
- If an active session already exists, "Edit APK" returns that session instead
  of creating another workspace.
- Users, sub-users, and multiple browser windows operate on the same active
  session for the same source APK.
- All edit operations mutate the same `workspace/`.
- A session has a `dirty` flag. It starts as `false` and becomes `true` after
  any operation changes `workspace/`.

Session state should be persisted in the database and treated as the source of
truth. Filesystem directories are working artifacts, not the authority for
whether a session is active or saved.

Session states:

- `active`: session is editable.
- `saving`: save is running.
- `saved`: edited APK was generated.
- `save_failed`: save failed and the workspace is retained for retry.
- `closed_no_changes`: save was clicked without changes and temporary files
  were removed.
- `discarded`: session was abandoned and temporary files were removed.

Save and discard actions must use a lock keyed by `source_md5` to prevent two
requests from rebuilding or deleting the same active session at the same time.

## Frida Gadget Injection

Frida Gadget injection is an edit operation, not a save operation.

Behavior:

- Detect available APK ABIs from `workspace/lib/<abi>/`.
- If no native library directory exists, allow the user or API caller to select
  an ABI; default to `arm64-v8a`.
- Download or reuse the matching `libfrida-gadget.so` for each selected ABI.
- Place the gadget under `workspace/lib/<abi>/`.
- Add or update the gadget config file under the same ABI directory.
- Insert a `System.loadLibrary(...)` call into the application startup path,
  preferring the Application class and falling back to the launch Activity.
- Mark the session dirty.
- Record selected ABIs and injection state in session metadata.

The operation must be idempotent. Re-running it should not insert duplicate
load calls or duplicate metadata. If the gadget is already present, the
operation should report that state and update configuration if needed.

Advanced Frida hiding can be controlled by the obfuscation operation. When
enabled, the implementation may rename the gadget library and use the matching
load name, but this is higher risk and should be disabled by default.

## Obfuscation

Obfuscation is an edit operation against the active session workspace. It is
configurable, with stable defaults and optional stronger modes.

Default mode should prioritize installable, runnable output:

- Limit smali obfuscation to the app's own package namespace where possible.
- Skip Android framework packages, known third-party packages, manifest entry
  components, Android lifecycle methods, and obvious reflection-sensitive names.
- Start method obfuscation with private/internal methods.
- Preserve manifest-referenced classes unless the manifest and all references
  are updated together.
- Generate a mapping file for changed identifiers.

Supported obfuscation categories:

1. Smali obfuscation
   - Rename selected packages, classes, and methods.
   - Update references in smali files.
   - Preserve excluded classes and methods.

2. Resource and asset obfuscation
   - Stable default: rename low-risk assets only.
   - Advanced option: rename selected `res/` files and update XML references.
   - Skip launcher icon, manifest-facing resources, and resources likely to be
     loaded by fixed string names unless explicitly enabled.

3. Anti-analysis obfuscation
   - Insert inert smali classes or methods.
   - Optionally encode safe string literals and add runtime decode helpers.
   - Skip class names, resource IDs, manifest values, URL schemes, component
     names, and other high-risk strings by default.
   - Optional Frida hiding mode may rename gadget artifacts consistently.

Each obfuscation run records options, mapping files, and an operation summary
in the session logs and metadata. Re-running obfuscation should either use the
existing mapping idempotently or clearly start a new obfuscation pass without
corrupting references.

## Save, Signing, and Download

Save closes the current active editing session.

When `dirty=false`:

- Do not rebuild.
- Do not sign.
- Do not generate a new APK.
- Set state to `closed_no_changes`.
- Keep the database state record for audit/status history.
- Delete the whole session directory:

```text
uploads/<source_md5>/apk_editor/<session_id>/
```

When `dirty=true`:

1. Set state to `saving`.
2. Build with apktool:

   ```text
   apktool b workspace -o build/unsigned.apk
   ```

3. Align with zipalign:

   ```text
   zipalign -p 4 build/unsigned.apk build/aligned.apk
   ```

4. Sign with apksigner.
5. Write the final APK to:

   ```text
   uploads/<source_md5>/apk_editor/<session_id>/output/<source_md5>-edited.apk
   ```

6. Set state to `saved`.
7. Delete `workspace/` and `build/`.
8. Keep `output/` and `logs/`.

Signing options:

- Default: use a MobSF-managed debug keystore.
- Advanced: accept a user-supplied keystore, alias, store password, and key
  password for the current save operation.
- Passwords must be redacted from logs and should not be stored after the save
  completes.

On save failure:

- Set state to `save_failed`.
- Keep `workspace/`, `build/`, and `logs/`.
- Expose the failure summary to UI and API callers.
- Allow retry save or discard.

Download:

- Download is available only after a successful save.
- Download serves the generated APK from the session `output/` directory.
- Download does not import, rescan, or mutate the APK.

Discard:

- Discard deletes the whole session directory.
- Set state to `discarded`.
- Do not generate an APK.

## Web UI

Add an "APK Editor" card to the Android static analysis report page for APK
scans.

UI states:

- No active session:
  - Show "Edit APK".
- Active session:
  - Show status.
  - Show Frida Gadget injection controls.
  - Show obfuscation controls.
  - Show "Save", "Discard", and "View Logs".
- Save failed:
  - Show error summary.
  - Show "Retry Save", "Discard", and "View Logs".
- Saved:
  - Show "Download Edited APK".
  - Allow starting a new edit session.

Controls should call the REST endpoints so UI and API behavior stay aligned.

## REST API

Add REST endpoints equivalent to the UI actions:

```text
POST /api/v1/apk_editor/start
POST /api/v1/apk_editor/frida_gadget
POST /api/v1/apk_editor/obfuscate
POST /api/v1/apk_editor/save
POST /api/v1/apk_editor/discard
GET  /api/v1/apk_editor/status
GET  /api/v1/apk_editor/logs
GET  /api/v1/apk_editor/download
```

Common request parameters:

- `hash`: required source APK MD5.
- `session_id`: required for operations after start unless the endpoint is
  explicitly resolving the current active session.

API requirements:

- Use existing MobSF API key and authorization patterns.
- Require scan permission for editor operations.
- Validate that `hash` is a known APK scan.
- Validate that the requested session is the active session when editing.
- Reject operations against saved, discarded, or closed sessions.
- Return structured JSON with status, session state, operation summary, and
  safe error messages.

`download` may return a file response after successful save. It should return
a clear JSON or HTTP error when no saved artifact exists.

## Logging

The editor keeps both structured state and file logs.

Structured state should support UI/API queries:

- Source MD5.
- Session ID.
- State.
- Dirty flag.
- Created, updated, saved timestamps.
- Last error summary.
- Output APK path.
- Operation metadata.

File log:

```text
uploads/<source_md5>/apk_editor/<session_id>/logs/editor.log
```

Log entries should include:

- Session creation and apktool decompile stage.
- Frida Gadget operation summary.
- Obfuscation options and summary.
- Build, align, and sign stages.
- Download events.
- Discard events.
- Errors with command stage and exit code.

Logs must redact:

- Keystore passwords.
- Key passwords.
- Authorization headers.
- API keys.

The UI and API log readers should expose user-safe logs. Full internal tracebacks
can remain in server logs when needed, but should not leak secrets to users.

## Implementation Notes

Existing project pieces to reuse:

- `mobsf/StaticAnalyzer/views/android/apk.py` for Android APK scan context.
- `mobsf/StaticAnalyzer/views/android/converter.py` for apktool patterns.
- `mobsf/DynamicAnalyzer/tools/apk_patcher.py` as a starting point for Frida
  Gadget download/decompile/recompile logic, after fixing its path and version
  assumptions.
- `mobsf/MobSF/views/home.py` download helpers where appropriate.
- `mobsf/MobSF/views/authorization.py` permission helpers.
- Existing `apksigner.jar`, Android build-tools, apktool, and Java runtime in
  the Docker image/source tree.

The editor should be implemented as a small service layer rather than placing
all behavior directly in Django views. Suggested modules:

- Session repository/state management.
- Filesystem workspace manager.
- Frida Gadget operation.
- Obfuscation operation.
- Build/sign operation.
- UI views and API views.

## Test Plan

Unit tests:

- Starting an edit session creates a workspace.
- Starting again for the same source APK returns the active session.
- Saving a clean session closes it and deletes the session directory.
- Dirty save invokes build/sign stages and preserves output/logs.
- Discard deletes the session directory.
- Operations reject invalid hashes and inactive sessions.
- Logs redact secrets.

Focused integration tests with command wrappers mocked:

- Frida injection is idempotent.
- Obfuscation marks the session dirty and writes mapping metadata.
- Save failure keeps workspace and allows retry.
- Saved session exposes download metadata.

Docker/manual verification:

- Upload an APK.
- Open the static analysis page.
- Start editing.
- Inject Frida Gadget.
- Run default obfuscation.
- Save with debug signing.
- Download the edited APK.
- Confirm no automatic rescan is triggered.
- Confirm no-change save deletes its temporary session directory.
