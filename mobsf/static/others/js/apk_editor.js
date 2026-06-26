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

  function message(name, fallback) {
    return root.dataset[name] || fallback;
  }

  function pageCsrfToken() {
    if (typeof csrf !== 'undefined') {
      return csrf;
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

  function updateControls(busy) {
    const editing = Boolean(sessionId);
    startBtn.disabled = busy || editing;
    fridaBtn.disabled = busy || !editing;
    obfuscateBtn.disabled = busy || !editing;
    saveBtn.disabled = busy || !editing;
    discardBtn.disabled = busy || !editing;
    if (!editing) {
      downloadLink.classList.add('disabled');
    }
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

  startBtn.addEventListener('click', function () {
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
      sessionId = data.session_id;
      setStatus(
        message(
          'msgEditing',
          'Editing. All operations will be saved to the current session.',
        ),
        'success',
      );
      updateControls(false);
    }).catch(() => {
      setStatus(message('msgStartFailed', 'Failed to enter edit mode'), 'danger');
      updateControls(false);
    });
  });

  fridaBtn.addEventListener('click', function () {
    if (!sessionId) {
      setStatus(message('msgNoSession', 'No active editor session'), 'warning');
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
          data.error || message('msgFridaFailed', 'Failed to inject Frida Gadget'),
          'danger',
        );
        updateControls(false);
        return;
      }
      setStatus(message('msgFridaDone', 'Frida Gadget injected'), 'success');
      updateControls(false);
    }).catch(() => {
      setStatus(
        message('msgFridaFailed', 'Failed to inject Frida Gadget'),
        'danger',
      );
      updateControls(false);
    });
  });

  obfuscateBtn.addEventListener('click', function () {
    if (!sessionId) {
      setStatus(message('msgNoSession', 'No active editor session'), 'warning');
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
        updateControls(false);
        return;
      }
      setStatus(message('msgObfuscateDone', 'Obfuscation complete'), 'success');
      updateControls(false);
    }).catch(() => {
      setStatus(
        message('msgObfuscateFailed', 'Failed to run obfuscation'),
        'danger',
      );
      updateControls(false);
    });
  });

  discardBtn.addEventListener('click', function () {
    if (!sessionId) {
      setStatus(message('msgNoSession', 'No active editor session'), 'warning');
      return;
    }
    updateControls(true);
    postForm(root.dataset.discardUrl, {
      hash: sourceHash,
      session_id: sessionId,
    }).then((data) => {
      if (data.status !== 'ok') {
        setStatus(
          data.error || message('msgDiscardFailed', 'Failed to discard edit session'),
          'danger',
        );
        updateControls(false);
        return;
      }
      sessionId = '';
      setStatus(message('msgDiscarded', 'Edit session discarded'), 'secondary');
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
