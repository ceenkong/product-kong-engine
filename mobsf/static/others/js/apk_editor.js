(function () {
  const root = document.getElementById('apk-editor');
  if (!root) {
    return;
  }

  let sourceHash = root.dataset.hash || '';
  const uploadForm = document.getElementById('apk-editor-upload');
  const uploadInput = document.getElementById('apk-editor-file');
  const uploadButton = document.getElementById('apk-editor-upload-button');
  const uploadProgress = document.getElementById('apk-editor-upload-progress');
  const uploadProgressBar = document.getElementById(
    'apk-editor-upload-progress-bar',
  );
  const uploadProgressText = document.getElementById(
    'apk-editor-upload-progress-text',
  );
  const statusBox = document.getElementById('apk-editor-status');
  const startBtn = document.getElementById('apk-editor-start');
  const fridaBtn = document.getElementById('apk-editor-frida');
  const obfuscateBtn = document.getElementById('apk-editor-obfuscate');
  const saveBtn = document.getElementById('apk-editor-save');
  const discardBtn = document.getElementById('apk-editor-discard');
  const downloadLink = document.getElementById('apk-editor-download');
  const logBox = document.getElementById('apk-editor-log');
  let sessionId = '';
  let savedDownloadUrl = '';

  function message(name, fallback) {
    return root.dataset[name] || fallback;
  }

  function pageCsrfToken() {
    if (typeof csrf !== 'undefined') {
      return csrf;
    }
    const input = document.querySelector('input[name=csrfmiddlewaretoken]');
    if (input && input.value) {
      return input.value;
    }
    return '';
  }

  function csrfToken() {
    const match = document.cookie.match(/csrftoken=([^;]+)/);
    if (match) {
      return decodeURIComponent(match[1]);
    }
    const token = pageCsrfToken();
    if (token) {
      document.cookie = `csrftoken=${encodeURIComponent(token)}; path=/`;
    }
    return token;
  }

  function setStatus(text, kind) {
    statusBox.className = `alert alert-${kind || 'secondary'}`;
    statusBox.textContent = text;
  }

  function setUploadProgress(percent, visible) {
    const value = Math.max(0, Math.min(100, Math.round(percent || 0)));
    const label = `${value}%`;
    if (uploadProgress) {
      uploadProgress.classList.toggle('d-none', !visible);
    }
    if (uploadProgressBar) {
      uploadProgressBar.style.width = label;
      uploadProgressBar.setAttribute('aria-valuenow', String(value));
      uploadProgressBar.textContent = label;
    }
    if (uploadProgressText) {
      uploadProgressText.textContent = label;
    }
  }

  function updateControls(busy) {
    const editing = Boolean(sessionId);
    startBtn.disabled = busy || editing || !sourceHash;
    fridaBtn.disabled = busy || !editing;
    obfuscateBtn.disabled = busy || !editing;
    saveBtn.disabled = busy || !editing;
    discardBtn.disabled = busy || !editing;

    if (savedDownloadUrl) {
      downloadLink.href = savedDownloadUrl;
      downloadLink.classList.remove('disabled');
    } else {
      downloadLink.href = '#';
      downloadLink.classList.add('disabled');
    }
  }

  function closeEditing() {
    sessionId = '';
    updateControls(false);
  }

  function downloadUrlFor(savedSessionId) {
    const params = new URLSearchParams({
      hash: sourceHash,
      session_id: savedSessionId,
    });
    return `${root.dataset.downloadUrl}?${params.toString()}`;
  }

  function loadLogs(logSessionId) {
    const targetSessionId = logSessionId || sessionId;
    if (!targetSessionId || !root.dataset.logsUrl || !logBox) {
      return Promise.resolve();
    }

    const params = new URLSearchParams({
      hash: sourceHash,
      session_id: targetSessionId,
    });
    return fetch(`${root.dataset.logsUrl}?${params.toString()}`)
      .then((response) => response.json())
      .then((data) => {
        logBox.classList.remove('d-none');
        logBox.textContent = data.logs || '';
      })
      .catch(() => {});
  }

  function postForm(url, data) {
    const token = csrfToken();
    const body = new URLSearchParams(data);
    body.set('csrfmiddlewaretoken', token);
    return fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-CSRFToken': token,
      },
      body,
    }).then((response) => {
      const contentType = response.headers && response.headers.get
        ? response.headers.get('content-type') || ''
        : '';
      if (!contentType.includes('application/json')) {
        throw new Error('Unexpected response');
      }
      return response.json();
    });
  }

  function uploadApk(body, token) {
    return new Promise((resolve, reject) => {
      const request = new XMLHttpRequest();
      request.open('POST', root.dataset.uploadUrl);
      request.setRequestHeader('X-CSRFToken', token);
      request.upload.onprogress = function (event) {
        if (event.lengthComputable) {
          setUploadProgress((event.loaded / event.total) * 100, true);
        }
      };
      request.onload = function () {
        if (request.status < 200 || request.status >= 300) {
          reject(new Error('Upload failed'));
          return;
        }
        try {
          resolve(JSON.parse(request.responseText || '{}'));
        } catch (error) {
          reject(error);
        }
      };
      request.onerror = function () {
        reject(new Error('Upload failed'));
      };
      request.onabort = function () {
        reject(new Error('Upload aborted'));
      };
      request.send(body);
    });
  }

  if (uploadInput) {
    uploadInput.addEventListener('change', function () {
      const fileName = uploadInput.files && uploadInput.files.length
        ? uploadInput.files[0].name
        : '';
      const label = uploadInput
        .closest('.custom-file')
        .querySelector('.custom-file-label');
      if (label && fileName) {
        label.textContent = fileName;
      }
      setUploadProgress(0, false);
    });
  }

  if (uploadForm) {
    uploadForm.addEventListener('submit', function (event) {
      event.preventDefault();
      if (!uploadInput || !uploadInput.files || !uploadInput.files.length) {
        setStatus(
          message('msgUploadFailed', 'Failed to upload APK'),
          'warning',
        );
        return;
      }

      updateControls(true);
      if (uploadButton) {
        uploadButton.disabled = true;
      }
      setStatus(message('msgUploading', 'Uploading APK'), 'info');
      setUploadProgress(0, true);

      const token = csrfToken();
      const body = new FormData(uploadForm);
      body.set('csrfmiddlewaretoken', token);
      uploadApk(body, token).then((data) => {
        if (data.status !== 'ok') {
          setStatus(
            data.error || message('msgUploadFailed', 'Failed to upload APK'),
            'danger',
          );
          setUploadProgress(0, false);
          updateControls(false);
          if (uploadButton) {
            uploadButton.disabled = false;
          }
          return;
        }

        sourceHash = data.hash;
        root.dataset.hash = sourceHash;
        savedDownloadUrl = '';
        sessionId = data.session_id;
        setUploadProgress(100, true);
        setStatus(
          message(
            'msgUploadDone',
            'APK uploaded. Editing session created.',
          ),
          'success',
        );
        updateControls(false);
        if (uploadButton) {
          uploadButton.disabled = false;
        }
        loadLogs();
      }).catch(() => {
        setStatus(
          message('msgUploadFailed', 'Failed to upload APK'),
          'danger',
        );
        setUploadProgress(0, false);
        updateControls(false);
        if (uploadButton) {
          uploadButton.disabled = false;
        }
      });
    });
  }

  startBtn.addEventListener('click', function () {
    if (!sourceHash) {
      setStatus(
        message('msgUploadFailed', 'Failed to upload APK'),
        'warning',
      );
      return;
    }
    updateControls(true);
    setStatus(message('msgStarting', 'Entering edit mode'), 'info');
    postForm(root.dataset.startUrl, { hash: sourceHash }).then((data) => {
      if (data.status !== 'ok') {
        setStatus(
          data.error || message('msgStartFailed', 'Failed to enter edit mode'),
          'danger',
        );
        updateControls(false);
        return;
      }
      savedDownloadUrl = '';
      sessionId = data.session_id;
      setStatus(
        message(
          'msgEditing',
          'Editing. All operations will be saved to the current session.',
        ),
        'success',
      );
      updateControls(false);
      loadLogs();
    }).catch(() => {
      setStatus(
        message('msgStartFailed', 'Failed to enter edit mode'),
        'danger',
      );
      updateControls(false);
    });
  });

  fridaBtn.addEventListener('click', function () {
    if (!sessionId) {
      setStatus(
        message('msgNoSession', 'No active editor session'),
        'warning',
      );
      return;
    }
    updateControls(true);
    setStatus(message('msgFridaStarting', 'Injecting Frida Gadget'), 'info');
    postForm(root.dataset.fridaUrl, {
      hash: sourceHash,
      session_id: sessionId,
    }).then((data) => {
      if (data.status !== 'ok') {
        setStatus(
          data.error || message(
            'msgFridaFailed',
            'Failed to inject Frida Gadget',
          ),
          'danger',
        );
        loadLogs();
        updateControls(false);
        return;
      }
      savedDownloadUrl = '';
      setStatus(message('msgFridaDone', 'Frida Gadget injected'), 'success');
      loadLogs();
      updateControls(false);
    }).catch(() => {
      setStatus(
        message('msgFridaFailed', 'Failed to inject Frida Gadget'),
        'danger',
      );
      loadLogs();
      updateControls(false);
    });
  });

  obfuscateBtn.addEventListener('click', function () {
    if (!sessionId) {
      setStatus(
        message('msgNoSession', 'No active editor session'),
        'warning',
      );
      return;
    }
    updateControls(true);
    setStatus(message('msgObfuscating', 'Running obfuscation'), 'info');
    postForm(root.dataset.obfuscateUrl, {
      hash: sourceHash,
      session_id: sessionId,
      assets: '1',
      anti_analysis: '1',
      smali: '0',
      resources: '0',
      frida_hide: '0',
    }).then((data) => {
      if (data.status !== 'ok') {
        setStatus(
          data.error || message(
            'msgObfuscateFailed',
            'Failed to run obfuscation',
          ),
          'danger',
        );
        loadLogs();
        updateControls(false);
        return;
      }
      savedDownloadUrl = '';
      setStatus(
        message('msgObfuscateDone', 'Obfuscation complete'),
        'success',
      );
      loadLogs();
      updateControls(false);
    }).catch(() => {
      setStatus(
        message('msgObfuscateFailed', 'Failed to run obfuscation'),
        'danger',
      );
      loadLogs();
      updateControls(false);
    });
  });

  saveBtn.addEventListener('click', function () {
    if (!sessionId) {
      setStatus(
        message('msgNoSession', 'No active editor session'),
        'warning',
      );
      return;
    }

    const savingSessionId = sessionId;
    updateControls(true);
    setStatus(message('msgSaving', 'Saving and signing'), 'info');
    postForm(root.dataset.saveUrl, {
      hash: sourceHash,
      session_id: savingSessionId,
      signing: 'debug',
    }).then((data) => {
      if (data.status !== 'ok') {
        setStatus(
          data.error || message('msgSaveFailed', 'Failed to save APK'),
          'danger',
        );
        loadLogs(savingSessionId);
        updateControls(false);
        return;
      }

      if (data.state === 'closed_no_changes') {
        savedDownloadUrl = '';
        setStatus(
          message(
            'msgClosedNoChanges',
            'No changes. Edit session closed.',
          ),
          'secondary',
        );
        loadLogs(savingSessionId);
        closeEditing();
        return;
      }

      savedDownloadUrl = downloadUrlFor(savingSessionId);
      setStatus(message('msgSaved', 'Saved. Download edited APK.'), 'success');
      loadLogs(savingSessionId);
      closeEditing();
    }).catch(() => {
      setStatus(message('msgSaveFailed', 'Failed to save APK'), 'danger');
      loadLogs(savingSessionId);
      updateControls(false);
    });
  });

  discardBtn.addEventListener('click', function () {
    if (!sessionId) {
      setStatus(
        message('msgNoSession', 'No active editor session'),
        'warning',
      );
      return;
    }
    updateControls(true);
    postForm(root.dataset.discardUrl, {
      hash: sourceHash,
      session_id: sessionId,
    }).then((data) => {
      if (data.status !== 'ok') {
        setStatus(
          data.error || message(
            'msgDiscardFailed',
            'Failed to discard edit session',
          ),
          'danger',
        );
        updateControls(false);
        return;
      }
      savedDownloadUrl = '';
      sessionId = '';
      setStatus(
        message('msgDiscarded', 'Edit session discarded'),
        'secondary',
      );
      updateControls(false);
    }).catch(() => {
      setStatus(
        message('msgDiscardFailed', 'Failed to discard edit session'),
        'danger',
      );
      updateControls(false);
    });
  });

  updateControls(false);
})();
