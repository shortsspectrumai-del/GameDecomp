/* GameDecomp Studio. No dependencies or remote assets. Credentials stay in memory. */
'use strict';
(() => {
  const $ = (id) => document.getElementById(id);
  const state = {
    token: null, connected: false, jobs: [], providers: [], binary: null, model: null,
    dataset: null, view: 'workspace', report: null, reportJob: null, trainingJob: null,
    activeFunction: null, activeType: null, typeIndex: new Map(), codeTab: 'baseline', functionLimit: 80,
    typeLimit: 100, reportCache: new Map(), autoOpen: new Set(), selectedJob: null,
    uploadVersion: 0, auxiliaryVersions: { model: 0, dataset: 0 }, reportVersion: 0,
    jobLimit: 50, jobsSignature: null, polling: false, submitting: false,
  };
  const viewNames = { workspace: 'Workspace', results: 'Results', types: 'Types & classes', training: 'GNN training', settings: 'Settings' };
  const kindNames = { analyze: 'Binary analysis', demo: 'Validated demo', translate: 'Function translation', gnn_demo: 'Demo corpus training', train_gnn: 'Dataset training' };
  const statusNames = { QUEUED: 'Queued', RUNNING: 'Running', SUCCEEDED: 'Completed', FAILED: 'Failed', CANCELLED: 'Cancelled' };
  const terminal = new Set(['SUCCEEDED', 'FAILED', 'CANCELLED']);
  const modelDefaults = { deepseek: '', openai: '', ollama: '', lmstudio: '', custom: '' };
  let toastTimer;
  let pollTimer;

  function node(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined && text !== null) element.textContent = String(text);
    return element;
  }
  function icon(name) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('class', 'icon');
    svg.setAttribute('aria-hidden', 'true');
    const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
    use.setAttribute('href', '#i-' + name);
    svg.append(use);
    return svg;
  }
  function button(text, className, action, iconName) {
    const element = node('button', className);
    element.type = 'button';
    if (iconName) element.append(icon(iconName));
    element.append(document.createTextNode(text));
    element.addEventListener('click', action);
    return element;
  }
  function safeText(value, fallback = '—') {
    return value === null || value === undefined || value === '' ? fallback : String(value);
  }
  function json(value) { return JSON.stringify(value, null, 2); }
  function address(value) {
    return typeof value === 'number' && Number.isFinite(value) ? '0x' + value.toString(16) : safeText(value);
  }
  function showError(error) {
    let message = typeof error === 'string' ? error : error.message || 'Operation failed.';
    const key = $('llm-key').value;
    if (key) message = message.split(key).join('[KEY REDACTED]');
    $('error-message').textContent = message.slice(0, 4000);
    $('error-banner').hidden = false;
  }
  function toast(message) {
    clearTimeout(toastTimer);
    $('toast').textContent = message;
    $('toast').hidden = false;
    toastTimer = setTimeout(() => { $('toast').hidden = true; }, 4500);
  }
  function connection(connected) {
    state.connected = connected;
    $('connection-dot').classList.toggle('offline', !connected);
    $('connection-label').textContent = connected ? 'Server connected' : 'Server unreachable';
    updateRunButton();
  }
  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (options.method && options.method !== 'GET') {
      if (!state.token) throw new Error('Connection not ready. Wait for the local server.');
      headers.set('X-GameDecomp-Token', state.token);
    }
    let response;
    try {
      response = await fetch(path, { ...options, headers, cache: 'no-store', credentials: 'same-origin', redirect: 'error' });
    } catch (error) {
      connection(false);
      throw new Error('The local server is unreachable. Check that GameDecomp Studio is running.');
    }
    let data;
    try { data = await response.json(); } catch (error) { throw new Error('The server returned an invalid response.'); }
    if (!response.ok) throw new Error(data.error || 'Request failed (' + response.status + ').');
    connection(true);
    return data;
  }
  async function post(path, value) {
    return api(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(value) });
  }
  const preferenceKey = 'gamedecomp.studio.preferences.v1';
  const preferenceFields = ['backend','workers','timeout','phase-timeout','max-types','recover-types','gnn-model','provider','llm-api-format','llm-context-bytes','llm-reasoning-effort','llm-json-mode','llm-temperature'];
  const localDefaults = { ollama: 'http://127.0.0.1:11434/v1', lmstudio: 'http://127.0.0.1:1234/v1' };
  let discoveryRevision = 0;

  function localEndpoint(value) {
    try { const url = new URL(value); return ['http:','https:'].includes(url.protocol) && (['localhost','[::1]','::1'].includes(url.hostname) || /^127\.\d+\.\d+\.\d+$/.test(url.hostname)); }
    catch (error) { return false; }
  }
  function safePreferenceEndpoint(value) {
    try {
      const url = new URL(value);
      if (!['http:','https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || /sk-[a-z0-9]{12,}/i.test(value)) return '';
      return url.origin + url.pathname;
    } catch (error) { return ''; }
  }
  function updateProviderLocation() {
    const enabled = $('provider').value !== 'off';
    const local = localEndpoint($('llm-url').value);
    $('provider-location').textContent = !enabled ? 'STATIC ANALYSIS · no LLM provider selected' : local ? 'LOCAL · loopback endpoint on this device' : 'REMOTE · selected function context leaves this device';
    $('provider-location').classList.toggle('is-local', enabled && local);
    $('llm-key').placeholder = local ? 'Optional for a local server' : 'API key or server environment variable';
  }
  function moveSettingsControls(name) {
    $(''+(name === 'settings' ? 'settings' : 'workspace')+'-provider-slot').append($('provider-controls'));
    $(''+(name === 'settings' ? 'settings' : 'workspace')+'-analysis-slot').append($('analysis-controls'));
  }
  function resetModelDiscovery() {
    discoveryRevision += 1;
    $('discovered-models').replaceChildren();
    $('discovered-model-select').replaceChildren(node('option', '', 'Choose a model…'));
    $('discovered-model-select').firstChild.value = '';
    $('discovered-model-field').hidden = true;
    $('llm-connection-status').textContent = 'Connection not tested. Enter a model name manually or refresh models.';
    $('llm-connection-status').classList.remove('success','failed');
    $('test-llm-connection').disabled = false;
    $('refresh-llm-models').disabled = false;
  }
  async function discoverModels(testOnly = false) {
    const revision = ++discoveryRevision;
    const payload = { provider: $('provider').value, api_format: apiFormat(), url: $('llm-url').value.trim(), key: $('llm-key').value };
    if (payload.provider === 'off' || !payload.url) { $('llm-connection-status').textContent = 'Choose a provider and enter an API endpoint first.'; return; }
    $('test-llm-connection').disabled = true;
    $('refresh-llm-models').disabled = true;
    $('llm-connection-status').textContent = testOnly ? 'Testing the selected server…' : 'Requesting available models…';
    $('llm-connection-status').classList.remove('success','failed');
    try {
      const result = await post('/api/llm/models', payload);
      if (revision !== discoveryRevision) return;
      const models = Array.isArray(result.models) ? result.models.filter((model) => typeof model.id === 'string' && model.id.length <= 256 && (!payload.key || !model.id.includes(payload.key))).slice(0,128) : [];
      $('discovered-models').replaceChildren();
      $('discovered-model-select').replaceChildren(node('option', '', 'Choose a model…'));
      $('discovered-model-select').firstChild.value = '';
      for (const model of models) {
        const option = node('option', '', model.id); option.value = model.id;
        $('discovered-model-select').append(option);
        const suggestion = node('option'); suggestion.value = model.id;
        $('discovered-models').append(suggestion);
      }
      $('discovered-model-field').hidden = models.length === 0;
      const available = result.status === 'AVAILABLE';
      $('llm-connection-status').classList.toggle('success', available);
      $('llm-connection-status').classList.toggle('failed', !available);
      $('llm-connection-status').textContent = available ? 'Server responded · ' + models.length + ' model' + (models.length === 1 ? '' : 's') + ' reported.' + (result.truncated ? ' The list is partial; enter another model manually if needed.' : ' Select one or enter a model manually.') + ' Listing does not test decompilation quality.' : 'Model discovery is unavailable. Check the server, endpoint and credentials. You can still enter a model manually.';
    } catch (error) {
      if (revision !== discoveryRevision) return;
      $('llm-connection-status').classList.add('failed');
      $('llm-connection-status').textContent = 'Connection failed. Check the server and endpoint. Manual model entry remains available.';
    } finally {
      payload.key = '';
      if (revision === discoveryRevision) { $('test-llm-connection').disabled = false; $('refresh-llm-models').disabled = false; }
    }
  }
  function savePreferences() {
    const preferences = {};
    for (const id of preferenceFields) { const field = $(id); preferences[id] = field.type === 'checkbox' ? field.checked : field.value; }
    const endpoint = safePreferenceEndpoint($('llm-url').value);
    preferences['llm-url'] = $('llm-key').value && endpoint.includes($('llm-key').value) ? '' : endpoint;
    const model = $('llm-model').value.trim();
    if (model.length <= 256 && !/sk-[a-z0-9]{12,}/i.test(model) && (!$('llm-key').value || !model.includes($('llm-key').value))) preferences['llm-model'] = model;
    try { localStorage.setItem(preferenceKey, JSON.stringify(preferences)); $('preferences-status').textContent = 'Preferences saved on this browser. API keys were excluded.'; }
    catch (error) { $('preferences-status').textContent = 'Browser storage is unavailable. Your current settings remain in memory.'; }
  }
  function restorePreferences() {
    try {
      const raw = localStorage.getItem(preferenceKey);
      if (!raw || raw.length > 8192) return;
      const preferences = JSON.parse(raw);
      if (!preferences || typeof preferences !== 'object' || Array.isArray(preferences)) return;
      for (const id of preferenceFields) {
        const field = $(id); const value = preferences[id];
        if (field.type === 'checkbox' && typeof value === 'boolean') field.checked = value;
        else if (typeof value === 'string' && value.length <= 256) {
          if (field.tagName === 'SELECT' && ![...field.options].some((option) => option.value === value)) continue;
          if (field.type === 'number' && (!Number.isFinite(Number(value)) || value === '' || (field.min && Number(value) < Number(field.min)) || (field.max && Number(value) > Number(field.max)))) continue;
          field.value = value;
        }
      }
      providerChanged();
      const endpoint = safePreferenceEndpoint(preferences['llm-url']);
      if (endpoint && !payloadPresetMismatch($('provider').value, endpoint)) $('llm-url').value = endpoint;
      if (typeof preferences['llm-model'] === 'string' && preferences['llm-model'].length <= 256 && !/sk-[a-z0-9]{12,}/i.test(preferences['llm-model'])) $('llm-model').value = preferences['llm-model'];
      $('model-upload-field').hidden = $('gnn-model').value !== 'custom';
      updateProviderLocation();
      $('preferences-status').textContent = 'Saved preferences restored. API keys must be entered again.';
    } catch (error) { $('preferences-status').textContent = 'Saved preferences could not be restored. Current defaults are active.'; }
  }
  function payloadPresetMismatch(provider, endpoint) {
    if (['custom','ollama','lmstudio'].includes(provider)) return false;
    return state.providers.find((entry) => entry.id === provider)?.url !== endpoint;
  }
  function candidateStatus(candidate) {
    if (!candidate) return 'NO AI CANDIDATE';
    if (candidate.semantic_status === 'DISPROVED') return 'REJECTED · behavior mismatch';
    if (candidate.semantic_status === 'TESTED') return 'TESTED ON FINITE CASES';
    if (candidate.selection_eligible === false) return candidate.compilation?.status === 'COMPILE_FAILED' ? 'REJECTED · compilation failed · NOT EXPORTED' : 'VALIDATION UNAVAILABLE · NOT EXPORTED';
    return 'AI CANDIDATE · ' + safeText(candidate.compilation?.status, 'UNKNOWN') + ' · UNVERIFIED SEMANTICS';
  }
  function renderProgress() {
    const job = state.jobs.find((entry) => !terminal.has(entry.status) && entry.progress) || state.jobs.find((entry) => entry.id === state.reportJob?.id && entry.progress);
    $('analysis-progress').hidden = !job;
    if (!job) return;
    const progress = job.progress;
    const finished = terminal.has(job.status);
    $('progress-mode').textContent = finished ? 'FINAL JOB SNAPSHOT' : 'LIVE ANALYSIS';
    $('progress-job-status').textContent = statusNames[job.status] || job.status;
    const stage = String(progress.stage || job.phase || 'Intake');
    const stages = ['Intake','Analysis','Reconstruction','Validation','Export'];
    const current = /export|publish|complete/i.test(stage) ? 4 : /valid|compil|test/i.test(stage) ? 3 : /reconstruct|llm|ai/i.test(stage) ? 2 : /analy|context|recover|frontend/i.test(stage) ? 1 : 0;
    $('progress-stages').replaceChildren(...stages.map((name,index) => { const item = node('li', index === current ? 'current' : index < current ? 'completed' : '', name); if (index === current) item.setAttribute('aria-current','step'); return item; }));
    const count = (key) => Number.isSafeInteger(progress[key]) && progress[key] >= 0 ? progress[key] : null;
    const total = count('total_units'); const processed = count('processed_units');
    $('progress-summary').textContent = stage + ' · ' + (total === null ? 'Discovering functions; total not yet known.' : (processed ?? 0) + ' / ' + total + ' functions processed');
    const counts = [['compiled_units','Compiled'],['ai_compiled_units','AI compiled'],['tested_units','Finite-tested'],['rejected_units','Rejected'],['unknown_units','Unknown'],['pending_units','Pending']];
    $('progress-counts').replaceChildren(...counts.map(([key,label]) => metric(label,(key === 'pending_units' ? total === null ? null : Math.max(0,total-(processed ?? 0)) : count(key)) ?? '—','Functions')));
    const active = Array.isArray(progress.active_units) ? progress.active_units.slice(0,8) : [];
    $('progress-active').replaceChildren(...active.map((unit) => node('span','active-unit',String(unit.name || unit.id || 'Function').slice(0,128)+' · '+String(unit.stage || stage).slice(0,128))));
  }
  function dependencyState(fn) {
    if (fn.candidate?.semantic_status === 'DISPROVED') return 'rejected';
    if (fn.candidate?.semantic_status === 'TESTED') return 'tested';
    if (fn.candidate?.compilation?.status === 'COMPILED' && fn.candidate?.selection_eligible !== false) return 'compiled';
    if (!fn.candidate && fn.compilation?.status === 'COMPILED') return 'compiled';
    return 'unknown';
  }
  function renderDependencies() {
    const functions = Array.isArray(state.report?.functions) ? state.report.functions : [];
    $('dependency-panel').hidden = !functions.length || state.view !== 'results';
    if (!functions.length) return;
    const visible = functions.slice(0,24); const index = new Map(visible.map((fn,i) => [fn.id,i]));
    const namespace = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(namespace,'svg');
    const rows = Math.ceil(visible.length/3); const height = rows*86+32;
    svg.setAttribute('viewBox','0 0 960 '+height); svg.setAttribute('role','img');
    svg.setAttribute('aria-label','Observed function dependency graph, limited to 24 functions. Text descriptions are available below.');
    const positions = visible.map((fn,i) => ({x:24+(i%3)*314,y:24+Math.floor(i/3)*86}));
    let edges = 0;
    for (let i=0;i<visible.length;i++) for (const target of (visible[i].calls || []).slice(0,24)) {
      const j = index.get(target); if (j === undefined || edges >= 48) continue;
      const line = document.createElementNS(namespace,'path');
      line.setAttribute('d','M'+(positions[i].x+140)+' '+(positions[i].y+44)+' L'+(positions[j].x+140)+' '+positions[j].y);
      line.setAttribute('class','dependency-edge');svg.append(line);edges += 1;
    }
    const descriptions = node('ul','dependency-descriptions');
    for (let i=0;i<visible.length;i++) {
      const fn = visible[i]; const group = document.createElementNS(namespace,'g');
      group.setAttribute('class','dependency-node '+dependencyState(fn));
      const rect = document.createElementNS(namespace,'rect');rect.setAttribute('x',positions[i].x);rect.setAttribute('y',positions[i].y);rect.setAttribute('width','280');rect.setAttribute('height','48');rect.setAttribute('rx','8');
      const text = document.createElementNS(namespace,'text');text.setAttribute('x',positions[i].x+14);text.setAttribute('y',positions[i].y+29);text.textContent=String(fn.name || fn.id).slice(0,30);
      const title = document.createElementNS(namespace,'title');title.textContent=String(fn.name || fn.id)+' · '+dependencyState(fn);
      group.append(title,rect,text);svg.append(group);
      const calls = (fn.calls || []).filter((id) => index.has(id)).slice(0,24);
      descriptions.append(node('li','',String(fn.name || fn.id)+' · '+dependencyState(fn)+' · observed calls: '+(calls.join(', ') || 'none in this view')));
    }
    const detail = node('details','dependency-text');detail.append(node('summary','','Read graph as text'),descriptions);
    $('dependency-canvas').replaceChildren(svg,detail);
    $('dependency-total').textContent=visible.length+' / '+functions.length+' FUNCTIONS · '+edges+' EDGES';
  }

  function showView(name, updateHash = true) {
    if (!viewNames[name]) name = 'workspace';
    state.view = name;
    moveSettingsControls(name);
    renderDependencies();
    for (const key of Object.keys(viewNames)) $('view-' + key).hidden = key !== name;
    document.querySelectorAll('.nav-item[data-view]').forEach((item) => {
      const active = item.dataset.view === name;
      item.classList.toggle('active', active);
      if (active) item.setAttribute('aria-current', 'page');
      else item.removeAttribute('aria-current');
    });
    $('breadcrumb-current').textContent = viewNames[name];
    $('sidebar').classList.remove('open');
    $('menu-toggle').setAttribute('aria-expanded', 'false');
    if (updateHash && window.location.hash !== '#' + name) history.replaceState(null, '', '#' + name);
  }
  function updateRunButton() {
    const ready = state.connected && !!state.binary && !state.submitting;
    const customMissing = $('gnn-model').value === 'custom' && !state.model;
    const requiredProfile = state.binary?.info?.required_profile || '';
    const profileMismatch = !!state.binary && $('console-profile').value !== requiredProfile;
    $('analyze-button').disabled = !ready || customMissing || profileMismatch;
    $('run-caption').textContent = !state.connected ? 'Connecting to local server…' : state.submitting ? 'Submitting job…' : !state.binary ? 'Import a binary to begin' : profileMismatch ? 'Select the matching console loader profile or generic executable analysis' : customMissing ? 'Upload a GNN JSON model to continue' : 'Ready · the job will run in the background';
  }
  function bytes(size) {
    if (size < 1024) return size + ' B';
    if (size < 1024 ** 2) return (size / 1024).toFixed(1) + ' KB';
    return (size / 1024 ** 2).toFixed(1) + ' MB';
  }
  async function upload(file, kind) {
    const maximum = { binary: 256, model: 16, dataset: 64 }[kind] * 1024 ** 2;
    if (!file || file.size === 0) throw new Error('Choose a nonempty file.');
    if (file.size > maximum) throw new Error('The file exceeds the limit of ' + bytes(maximum) + '.');
    const profile = kind === 'binary' ? '&profile=' + encodeURIComponent($('console-profile').value) : '';
    return api('/api/upload?kind=' + kind + '&name=' + encodeURIComponent(file.name) + profile, { method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: file });
  }
  async function selectBinary(file) {
    const revision = ++state.uploadVersion;
    state.binary = null;
    updateRunButton();
    $('dropzone').classList.add('busy');
    $('drop-title').textContent = 'Importing…';
    $('drop-description').textContent = 'The local server is identifying your file.';
    $('selected-file').hidden = true;
    try {
      const uploaded = await upload(file, 'binary');
      if (revision !== state.uploadVersion) return;
      state.binary = uploaded;
      $('file-name').textContent = uploaded.name;
      const info = uploaded.info || {};
      $('file-meta').textContent = [bytes(uploaded.size), info.format, info.architecture].filter(Boolean).join(' · ');
      $('selected-file').hidden = false;
      toast('Binary imported. You can start analysis.');
    } catch (error) { if (revision === state.uploadVersion) showError(error); }
    finally {
      if (revision === state.uploadVersion) {
        $('dropzone').classList.remove('busy');
        resetDropzoneText();
        updateRunButton();
      }
    }
  }
  function resetDropzoneText() {
    $('drop-title').textContent = state.binary ? 'Analyze another binary?' : 'Drop your binary here';
    $('drop-description').replaceChildren(document.createTextNode('or '), node('span', 'mint-link', 'choose a file from your computer'));
  }
  function clearBinary() {
    state.uploadVersion += 1;
    state.binary = null;
    $('binary-file').value = '';
    $('selected-file').hidden = true;
    $('dropzone').classList.remove('busy');
    resetDropzoneText();
    updateRunButton();
  }
  async function selectAuxiliary(file, kind) {
    const revision = ++state.auxiliaryVersions[kind];
    const status = kind === 'model' ? $('model-upload-status') : $('dataset-status');
    state[kind] = null;
    status.textContent = 'Importing…';
    updateRunButton();
    try {
      const result = await upload(file, kind);
      if (revision !== state.auxiliaryVersions[kind]) return;
      state[kind] = result;
      status.textContent = result.name + ' · ' + bytes(result.size) + ' · imported';
      toast(kind === 'model' ? 'GNN model imported.' : 'Dataset imported.');
    } catch (error) {
      if (revision !== state.auxiliaryVersions[kind]) return;
      status.textContent = 'Import failed. Choose the file again.'; showError(error);
    }
    updateRunButton();
  }
  function providerChanged() {
    const id = $('provider').value;
    const enabled = id !== 'off';
    const provider = state.providers.find((entry) => entry.id === id);
    $('llm-fields').hidden = !enabled;
    $('llm-model').value = modelDefaults[id] || '';
    $('llm-model').placeholder = ['ollama','lmstudio'].includes(id) ? 'e.g. a model installed on your local server' : 'Model available on your account or local server';
    $('llm-model').required = enabled;
    $('llm-url').value = localDefaults[id] || provider?.url || '';
    $('llm-url').required = enabled;
    $('llm-url').readOnly = !['custom','ollama','lmstudio'].includes(id);
    if (id !== 'custom') $('llm-api-format').value = id === 'anthropic' ? 'anthropic' : 'openai';
    $('llm-api-format').disabled = id !== 'custom';
    updateApiCompatibility();
    $('llm-key').value = '';
    $('llm-key').placeholder = id === 'ollama' ? 'Optional for a local server' : 'API key or server environment variable';
    if (provider?.key_env) $('llm-key').title = 'If empty, the server may use ' + provider.key_env;
    else $('llm-key').removeAttribute('title');
    resetModelDiscovery();
    updateProviderLocation();
  }
  function apiFormat() {
    return $('provider').value === 'anthropic' ? 'anthropic' : $('provider').value === 'custom' ? $('llm-api-format').value : 'openai';
  }
  function updateApiCompatibility() {
    const native = apiFormat() === 'anthropic';
    $('llm-reasoning-effort').disabled = native;
    if (native) $('llm-reasoning-effort').value = 'auto';
    $('llm-json-mode').disabled = native;
    if (native) $('llm-json-mode').value = 'prompt';
    $('llm-temperature').max = native ? '1' : '2';
    $('llm-protocol-note').textContent = native ? 'Native Anthropic Messages API with prompt JSON and strict local response validation. Extended thinking is not configured; reasoning effort is omitted.' : 'OpenAI-compatible Chat Completions API. Use prompt JSON mode for servers without response_format.';
  }
  function analysisOptions() {
    const modelKind = $('gnn-model').value;
    if (modelKind === 'custom' && !state.model) throw new Error('Upload your custom GNN model.');
    const provider = $('provider').value;
    const options = {
      backend: $('backend').value,
      console_profile: $('console-profile').value || null,
      workers: Number($('workers').value), timeout: Number($('timeout').value),
      phase_timeout: Number($('phase-timeout').value), function_pattern: $('function-pattern').value.trim() || null,
      recover_types: $('recover-types').checked, max_types: Number($('max-types').value),
      llm_context_bytes: Number($('llm-context-bytes').value),
      gnn_model: modelKind === 'builtin' ? 'builtin' : null,
      llm: { provider },
    };
    if (modelKind === 'custom') options.model_file_id = state.model.file_id;
    if (provider !== 'off') {
      options.llm.model = $('llm-model').value.trim();
      options.llm.url = $('llm-url').value.trim();
      options.llm.key = $('llm-key').value;
      options.llm.api_format = apiFormat();
      options.llm.json_mode = $('llm-json-mode').value;
      const effort = $('llm-reasoning-effort').value;
      if (options.llm.api_format !== 'anthropic' && effort !== 'auto') options.llm.reasoning_effort = effort;
      const temperature = $('llm-temperature').value.trim();
      if (temperature !== '') options.llm.temperature = Number(temperature);
      if (!options.llm.model) throw new Error('Enter an LLM model name.');
    }
    return options;
  }
  async function submitJob(value) {
    const data = await post('/api/jobs', value);
    const job = data.job;
    state.autoOpen.add(job.id);
    state.jobs = [job, ...state.jobs.filter((entry) => entry.id !== job.id)];
    renderJobs();
    toast('Job started. You can keep exploring Studio.');
    schedulePoll(300);
    return job;
  }
  async function analyze(event) {
    event.preventDefault();
    if (state.submitting) return;
    if (!state.binary) { showError('Import a binary before starting analysis.'); return; }
    let value;
    try { value = { kind: 'analyze', file_id: state.binary.file_id, options: analysisOptions() }; }
    catch (error) { showError(error); return; }
    state.submitting = true;
    updateRunButton();
    try { await submitJob(value); }
    catch (error) {
      const secret = value.options.llm.key;
      const message = secret ? error.message.split(secret).join('[KEY REDACTED]') : error.message;
      showError(message);
    } finally {
      $('llm-key').value = '';
      if (value.options.llm) delete value.options.llm.key;
      state.submitting = false;
      updateRunButton();
    }
  }
  async function demo() {
    const buttons = [$('top-demo'), $('workspace-demo')];
    buttons.forEach((item) => { item.disabled = true; });
    try { await submitJob({ kind: 'demo', options: { workers: Number($('workers').value), timeout: 300 } }); }
    catch (error) { showError(error); }
    finally { buttons.forEach((item) => { item.disabled = false; }); }
  }
  async function train(event) {
    event.preventDefault();
    const kind = $('training-kind').value;
    if (kind === 'train_gnn' && !state.dataset) { showError('Upload a JSON dataset before starting training.'); return; }
    $('training-button').disabled = true;
    try {
      const value = { kind, epochs: Number($('training-epochs').value), seed: Number($('training-seed').value), options: { timeout: 600 } };
      if (kind === 'train_gnn') value.file_id = state.dataset.file_id;
      else value.samples = Number($('training-samples').value);
      await submitJob(value);
    } catch (error) { showError(error); }
    finally { $('training-button').disabled = false; }
  }
  function historyJobs(jobs, query, status) {
    const search = String(query || '').trim().toLocaleLowerCase('en');
    const wanted = String(status || 'all').toUpperCase();
    return jobs.filter((job) => {
      const matchesStatus = wanted === 'ALL' || (wanted === 'RUNNING' ? job.status === 'RUNNING' || job.status === 'QUEUED' : job.status === wanted);
      const searchable = [job.id, job.kind, kindNames[job.kind], job.phase].filter(Boolean).join(' ').toLocaleLowerCase('en');
      return matchesStatus && (!search || searchable.includes(search));
    });
  }
  function renderJobs() {
    renderProgress();
    const query = $('history-search').value;
    const status = $('history-status').value;
    const signature = JSON.stringify([state.jobLimit, query, status, state.jobs]);
    if (signature === state.jobsSignature) return;
    state.jobsSignature = signature;
    const matching = historyJobs(state.jobs, query, status);
    const visible = matching.slice(0, state.jobLimit);
    $('job-count').textContent = state.jobs.length + (state.jobs.length === 1 ? ' JOB' : ' JOBS');
    $('activity-empty').hidden = state.jobs.length > 0;
    $('history-no-match').hidden = !state.jobs.length || matching.length > 0;
    $('history-summary').textContent = 'Showing ' + visible.length + ' of ' + matching.length + ' matching jobs · ' + state.jobs.length + ' total';
    const fragment = document.createDocumentFragment();
    // Mount history in bounded batches while retaining access to older jobs.
    for (const job of visible) {
      const card = node('article', 'job-card');
      const running = job.status === 'RUNNING' || job.status === 'QUEUED';
      const success = job.status === 'SUCCEEDED';
      const failed = job.status === 'FAILED';
      const indicator = node('span', 'job-indicator' + (running ? ' running' : success ? ' success' : failed ? ' failed' : ''));
      if (!running) indicator.append(icon(success ? 'check' : failed ? 'info' : 'close'));
      indicator.setAttribute('aria-hidden', 'true');
      const info = node('div', 'job-info');
      const name = node('span', 'job-name', kindNames[job.kind] || job.kind);
      if (job.restored) name.append(node('span', 'job-restored', 'Restored job'));
      info.append(name);
      const timestamp = new Date(job.created_at);
      const time = Number.isNaN(timestamp.getTime()) ? '' : timestamp.toLocaleString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
      info.append(node('span', 'job-phase', [job.phase, time, '#' + job.id.slice(0, 7)].filter(Boolean).join(' · ')));
      const actions = node('div', 'job-actions');
      actions.append(node('span', 'job-status' + (success ? ' success' : failed ? ' failed' : ''), statusNames[job.status] || job.status));
      actions.append(button('Log', 'button button-small button-ghost', () => selectJob(job.id)));
      if (running) actions.append(button('Cancel', 'button button-small button-ghost', () => cancelJob(job.id)));
      if (success) actions.append(button('Open results', 'button button-small button-secondary', () => openReport(job), 'arrow'));
      card.append(indicator, info, actions);
      fragment.append(card);
    }
    if (matching.length > state.jobLimit) fragment.append(button('Show earlier jobs', 'button button-ghost load-more', () => { state.jobLimit += 50; renderJobs(); }));
    $('jobs-list').replaceChildren(fragment);
    if (state.selectedJob) selectJob(state.selectedJob, false);
  }
  function selectJob(id, expand = true) {
    const job = state.jobs.find((entry) => entry.id === id);
    if (!job) return;
    state.selectedJob = id;
    $('job-detail').hidden = false;
    if (expand) $('job-detail').open = true;
    $('job-detail-title').textContent = (kindNames[job.kind] || job.kind) + ' · #' + id.slice(0, 7) + ' · ' + (statusNames[job.status] || job.status);
    const logs = [job.phase, ...(job.logs || []).slice(-100)];
    if (job.error) logs.push('Error: ' + job.error);
    if (job.result?.summary) logs.push(json(job.result.summary));
    $('job-detail-log').textContent = logs.filter(Boolean).join('\n');
  }
  async function cancelJob(id) {
    try {
      const result = await post('/api/jobs/' + encodeURIComponent(id) + '/cancel', {});
      state.jobs = state.jobs.map((job) => job.id === id ? result.job : job);
      state.autoOpen.delete(id);
      renderJobs();
      toast('Cancellation requested.');
    } catch (error) { showError(error); }
  }
  function schedulePoll(delay = 1500) {
    clearTimeout(pollTimer);
    pollTimer = setTimeout(poll, delay);
  }
  async function poll() {
    if (!state.token) { await bootstrap(false); return; }
    if (state.polling) { schedulePoll(); return; }
    state.polling = true;
    try {
      const data = await api('/api/jobs');
      state.jobs = Array.isArray(data.jobs) ? data.jobs : [];
      renderJobs();
      for (const job of state.jobs) {
        if (state.autoOpen.has(job.id) && terminal.has(job.status)) {
          state.autoOpen.delete(job.id);
          if (job.status === 'SUCCEEDED') await openReport(job);
          else if (job.status === 'FAILED') { showError(job.error || 'The job failed. Check its log.'); selectJob(job.id); }
        }
      }
    } catch (error) { /* The persistent connection indicator reports a stopped server without repeating alerts. */ }
    finally {
      state.polling = false;
      const active = state.jobs.some((job) => !terminal.has(job.status));
      schedulePoll(active ? 1200 : 5000);
    }
  }
  async function openReport(job, navigate = true) {
    const revision = ++state.reportVersion;
    try {
      let report = state.reportCache.get(job.id);
      if (!report) {
        report = await api('/api/jobs/' + encodeURIComponent(job.id) + '/report');
        state.reportCache.set(job.id, report);
        if (state.reportCache.size > 12) state.reportCache.delete(state.reportCache.keys().next().value);
      }
      if (revision !== state.reportVersion) return;
      if (job.kind === 'train_gnn' || job.kind === 'gnn_demo') {
        state.trainingJob = job;
        renderTraining(report, job);
        if (navigate) showView('training');
      } else {
        state.report = report;
        state.reportJob = job;
        state.typeIndex = new Map((report.type_recovery?.types || []).map((type) => [type.id, type]));
        state.activeFunction = report.functions?.[0]?.id ?? null;
        state.codeTab = report.engine?.mode === 'LLM' ? 'candidate' : 'baseline';
        state.activeType = report.type_recovery?.types?.[0]?.id ?? null;
        state.functionLimit = 80;
        state.typeLimit = 100;
        $('function-search').value = '';
        $('type-search').value = '';
        renderReport();
        renderTypes();
        if (navigate) showView('results');
      }
    } catch (error) { showError(error); }
  }
  function metric(label, value, note) {
    const card = node('div', 'metric-card');
    card.append(node('span', 'metric-label', label), node('div', 'metric-value', safeText(value)), node('p', 'metric-note', note));
    return card;
  }
  function localArtifact(job, suffix) {
    // IDs are encoded and paths constructed locally; never navigate to an arbitrary API-supplied URL.
    return '/api/jobs/' + encodeURIComponent(job.id) + '/' + suffix;
  }
  function renderReport() {
    const report = state.report;
    if (!report) return;
    const summary = report.summary || {};
    const functions = Array.isArray(report.functions) ? report.functions : [];
    $('results-empty').hidden = true;
    $('results-content').hidden = false;
    $('result-actions').hidden = false;
    $('report-link').href = localArtifact(state.reportJob, 'report.html');
    $('export-link').href = localArtifact(state.reportJob, 'export');
    $('export-link').setAttribute('download', 'gamedecomp-' + state.reportJob.id.slice(0, 7) + '.zip');
    const baselineTab = document.querySelector('[data-code="baseline"]');
    if (baselineTab) baselineTab.textContent = report.translation ? 'Translated source' : 'Baseline';
    $('nav-function-count').textContent = functions.length;
    $('result-metrics').replaceChildren(
      metric('Functions', summary.total ?? functions.length, report.translation ? 'Selected for translation' : 'Identified during analysis'),
      metric(report.translation ? 'Generated source' : 'Recovered baselines', summary.recovered, report.translation ? 'LLM translation; semantics unverified' : 'Conservative sources'),
      metric('Compiled', summary.compiled, 'Compilation check'),
      metric('SIMD compatibility', summary.compatibility_compiled ?? 0, 'Compiled translations; semantics unverified'),
      metric('AI candidates', summary.ai_candidates, 'Candidates require independent validation'),
    );
    const info = report.input || {};
    const meta = [info.format, info.architecture, report.backend, typeof report.timings?.total_seconds === 'number' ? report.timings.total_seconds.toFixed(2) + ' s' : null, report.cache_hit ? 'Analysis cache reused' : null];
    $('report-meta').replaceChildren(...meta.filter(Boolean).map((item) => node('span', '', item)));
    if (report.project) $('report-meta').append(node('span', '', 'CMake project in ZIP: ' + report.project.summary.exported_units + ' baseline units; complete recovery not established'));
    if (report.engine) $('report-meta').append(node('span', '', 'Engine: '+report.engine.mode+(report.engine.model ? ' · '+report.engine.model : ' · configure an LLM for AI reconstruction')));
    if (report.translation) $('report-meta').append(node('span', '', 'Function translation · ' + safeText(report.translation.target_language) + ' · behavioral equivalence not established'));
    const originId = report.translation?.source_job_id;
    $('translation-origin').hidden = !originId;
    $('translation-origin').disabled = !state.jobs.some((job) => job.id === originId && job.status === 'SUCCEEDED');
    if (report.ai_project) $('report-meta').append(node('span', '', 'project-ai in ZIP: '+report.ai_project.summary.exported_units+' eligible AI units; see finite validation status'));
    const limitations = [...(report.diagnostics || []), ...(report.type_recovery?.diagnostics || []), ...(report.gnn?.diagnostics || []), ...(report.limitations || [])];
    const list = node('ul');
    for (const text of limitations) list.append(node('li', '', text));
    $('report-diagnostics').replaceChildren(list);
    renderFunctions();
    renderCode();
    renderDependencies();
  }
  function filteredFunctions() {
    const query = $('function-search').value.trim().toLocaleLowerCase('en');
    return (state.report?.functions || []).filter((entry) => !query || (safeText(entry.name, '') + ' ' + address(entry.address) + ' ' + entry.id).toLocaleLowerCase('en').includes(query));
  }
  function renderFunctions() {
    const functions = filteredFunctions();
    $('function-total').textContent = functions.length + ' ENTRIES';
    const fragment = document.createDocumentFragment();
    for (const fn of functions.slice(0, state.functionLimit)) {
      const item = button('', 'function-row' + (fn.id === state.activeFunction ? ' active' : ''), () => {
        state.activeFunction = fn.id; renderFunctions(); renderCode();
      });
      item.setAttribute('aria-pressed', String(fn.id === state.activeFunction));
      const text = node('span');
      text.append(node('span', 'function-row-title', fn.name || fn.id), node('span', 'function-row-meta', address(fn.address)));
      item.append(text);
      if (fn.source) item.append(node('span', 'function-row-badge', safeText(fn.metadata?.language, 'C')));
      fragment.append(item);
    }
    if (!functions.length) fragment.append(node('p', 'empty-message', 'No functions match your search.'));
    $('function-list').replaceChildren(fragment);
    $('function-more').hidden = functions.length <= state.functionLimit;
  }
  function translationSelection() {
    const fn = state.report?.functions?.find((entry) => entry.id === state.activeFunction);
    if (!state.reportJob || state.reportJob.status !== 'SUCCEEDED' || !['analyze', 'demo'].includes(state.reportJob.kind)) return { available: false, reason: 'Open an original analysis to translate one of its functions.' };
    if (!['baseline', 'candidate'].includes(state.codeTab)) return { available: false, reason: 'Select Baseline or AI reconstruction to translate source code.' };
    const sourceKind = state.codeTab === 'candidate' ? 'candidate' : 'baseline';
    const source = sourceKind === 'candidate' ? fn?.candidate?.source : fn?.source;
    if (!fn || !source) return { available: false, reason: 'Select a function with recovered source code.' };
    if (sourceKind === 'baseline' && fn.semantic_status === 'DISPROVED') return { available: false, reason: 'This source was disproved by validation. Select an eligible source.' };
    if (sourceKind === 'candidate' && fn.candidate.compilation?.status !== 'COMPILED') return { available: false, reason: 'Select an AI candidate that passed compilation.' };
    if (sourceKind === 'candidate' && (fn.candidate.semantic_status === 'DISPROVED' || fn.candidate.selection_eligible === false)) return { available: false, reason: 'This AI candidate was rejected by validation. Select an eligible source.' };
    if ($('provider').value === 'off') return { available: false, reason: 'Configure an LLM in Settings to translate this function.' };
    if (!['cpp', 'java'].includes($('translation-language').value)) return { available: false, reason: 'Choose C++ or Java as the target language.' };
    return { available: true, fn, sourceKind };
  }
  function updateTranslationControls() {
    const selection = translationSelection();
    $('translate-function').disabled = !selection.available || state.submitting;
    $('translation-status').textContent = state.submitting ? 'Submitting request…' : selection.available ? 'Translate the selected source. Compilation checks syntax; behavioral equivalence remains unverified.' : selection.reason;
  }
  async function translateFunction() {
    if (state.submitting) return;
    const selection = translationSelection();
    if (!selection.available) { updateTranslationControls(); return; }
    let value;
    try {
      value = { kind: 'translate', source_job_id: state.reportJob.id, function_id: selection.fn.id,
        target_language: $('translation-language').value, source_kind: selection.sourceKind, options: analysisOptions() };
    } catch (error) { showError(error); return; }
    state.submitting = true;
    updateRunButton(); updateTranslationControls();
    try { await submitJob(value); }
    catch (error) {
      const secret = value.options.llm.key;
      showError(secret ? error.message.split(secret).join('[KEY REDACTED]') : error.message);
    } finally {
      $('llm-key').value = '';
      if (value.options.llm) delete value.options.llm.key;
      state.submitting = false;
      updateRunButton(); updateTranslationControls();
    }
  }
  function renderCode() {
    updateTranslationControls();
    const fn = state.report?.functions?.find((entry) => entry.id === state.activeFunction);
    if (!fn) {
      $('function-name').textContent = 'No functions available';
      $('function-address').textContent = '';
      $('code-output').textContent = 'The backend found no functions in its supported subset. Check diagnostics and the full report.';
      $('code-status').textContent = 'NO SOURCE';
      return;
    }
    $('function-name').textContent = fn.name || fn.id;
    $('function-address').textContent = address(fn.address) + ' · ' + safeText(fn.metadata?.language, 'C') + ' · ' + fn.id;
    let content;
    let status;
    if (state.codeTab === 'baseline') {
      content = fn.source || '/* No conservative source recovered for this function.\n   See disassembly, evidence and diagnostics. */';
      status = (state.reportJob?.kind === 'translate' ? 'LLM TRANSLATION' : 'BASELINE') + ' · ' + safeText(fn.compilation?.status, 'UNKNOWN') + ' · SEMANTICS ' + safeText(fn.semantic_status, 'UNKNOWN');
    } else if (state.codeTab === 'compatibility') {
      content = fn.compatibility?.source || '/* No compatibility translation is available for this function. */';
      status = fn.compatibility ? 'COMPATIBILITY · ' + safeText(fn.compatibility.compilation?.status, fn.compatibility.status) + ' · UNVERIFIED SEMANTICS' : 'NO SIMD TRANSLATION';
    } else if (state.codeTab === 'candidate') {
      content = fn.candidate?.source || '/* No AI candidate is available.\n   Enable an LLM provider to generate candidates.\n   Candidates may also be absent when validation rejects them. */';
      status = candidateStatus(fn.candidate);
    } else if (state.codeTab === 'disassembly') {
      content = (fn.instructions || []).map((instruction) => address(instruction.address).padEnd(18) + safeText(instruction.mnemonic, '').padEnd(10) + safeText(instruction.operands, '')).join('\n') || 'The backend exported no disassembly.';
      status = 'BACKEND INSTRUCTIONS · ' + (fn.instructions || []).length + ' ENTRIES';
    } else {
      content = json({ diagnostics: fn.diagnostics, compilation: fn.compilation, compatibility: fn.compatibility, calls: fn.calls, metadata: fn.metadata, context: fn.context, ai_context: fn.ai_context, ai_attempts: fn.ai_attempts, candidate_evidence: fn.candidate?.evidence_ids, semantic_recovery: fn.candidate?.recovery, candidate_validation: fn.candidate?.semantic_validation || fn.candidate?.validation, candidate_selection_eligible: fn.candidate?.selection_eligible, rejected_candidates: fn.rejected_candidates });
      status = 'EVIDENCE & PROVENANCE · EXPLICIT HYPOTHESES';
    }
    $('code-output').textContent = content;
    $('code-output').scrollTop = 0;
    $('code-output').scrollLeft = 0;
    $('code-status').textContent = status;
    document.querySelectorAll('[data-code]').forEach((tab) => {
      const active = tab.dataset.code === state.codeTab;
      tab.classList.toggle('active', active);
      tab.setAttribute('aria-selected', String(active));
      tab.tabIndex = active ? 0 : -1;
    });
  }
  function section(title, content) {
    const element = node('section', 'type-content-section');
    element.append(node('h3', '', title), content);
    return element;
  }
  function table(headers, rows) {
    const wrapper = node('div', 'data-table-wrap');
    const element = node('table', 'data-table');
    const head = node('thead'); const headerRow = node('tr');
    for (const text of headers) { const cell = node('th', '', text); cell.scope = 'col'; headerRow.append(cell); }
    head.append(headerRow);
    const body = node('tbody');
    for (const row of rows) { const tr = node('tr'); for (const text of row) tr.append(node('td', '', safeText(text))); body.append(tr); }
    element.append(head, body); wrapper.append(element); return wrapper;
  }
  function typeName(id) {
    const type = state.typeIndex.get(id);
    return type ? type.qualified_name || type.name || type.id : safeText(id);
  }
  function renderTypes() {
    const types = state.report?.type_recovery?.types || [];
    $('types-empty').hidden = types.length > 0;
    $('types-content').hidden = types.length === 0;
    if (!types.length) return;
    const query = $('type-search').value.trim().toLocaleLowerCase('en');
    const filtered = types.filter((type) => !query || [type.qualified_name, type.name, type.kind, type.id].filter(Boolean).join(' ').toLocaleLowerCase('en').includes(query));
    $('type-total').textContent = filtered.length + ' ENTRIES';
    const fragment = document.createDocumentFragment();
    for (const type of filtered.slice(0, state.typeLimit)) {
      const row = button('', 'function-row' + (type.id === state.activeType ? ' active' : ''), () => { state.activeType = type.id; renderTypes(); });
      row.setAttribute('aria-pressed', String(type.id === state.activeType));
      const text = node('span');
      text.append(node('span', 'function-row-title', type.qualified_name || type.name || type.id), node('span', 'function-row-meta', [type.kind, type.status].filter(Boolean).join(' · ')));
      row.append(text); fragment.append(row);
    }
    if (!filtered.length) fragment.append(node('p', 'empty-message', 'No types match your search.'));
    $('type-list').replaceChildren(fragment);
    $('type-more').hidden = filtered.length <= state.typeLimit;
    const type = types.find((entry) => entry.id === state.activeType) || types[0];
    $('type-name').textContent = type.qualified_name || type.name || type.id;
    $('type-kind').textContent = safeText(type.kind);
    const content = document.createDocumentFragment();
    const summary = node('div', 'type-summary');
    summary.append(node('span', '', 'Status: ' + safeText(type.status)), node('span', '', 'Size: ' + safeText(type.byte_size ?? type.size_bytes) + ' byte'), node('span', '', 'ID: ' + type.id));
    content.append(section('Origin & layout', summary));
    if (type.target_type) content.append(section('Referenced type', node('pre', 'detail-code', typeName(type.target_type))));
    if (type.members?.length) content.append(section('Fields · ' + type.members.length, table(['Name', 'Type', 'Offset', 'Access'], type.members.map((member) => [member.name || '(anonymous)', typeName(member.type_id), member.offset_bytes ?? 'Unresolved', member.accessibility]))));
    if (type.bases?.length) content.append(section('Base classes', table(['Type', 'Offset', 'Inheritance'], type.bases.map((base) => [typeName(base.type_id), base.offset_bytes ?? 'Unresolved', [base.virtual ? 'virtual' : null, base.accessibility].filter(Boolean).join(' ')]))));
    if (type.methods?.length) content.append(section('Methods', table(['Name', 'Return type', 'Virtual slot'], type.methods.map((method) => [method.name || method.linkage_name, typeName(method.return_type), method.vtable_index]))));
    if (type.enumerators?.length) content.append(section('Enumeration values', table(['Name', 'Value'], type.enumerators.map((entry) => [entry.name, entry.value]))));
    if (type.vtables?.length) content.append(section('Virtual tables', node('pre', 'detail-code', json(type.vtables))));
    content.append(section('Evidence · complete record', node('pre', 'detail-code', json(type))));
    $('type-content').replaceChildren(content);
  }
  function percentage(value) { return typeof value === 'number' && Number.isFinite(value) ? (value * 100).toFixed(1) + '%' : '—'; }
  function decimal(value) { return typeof value === 'number' && Number.isFinite(value) ? value.toFixed(4) : '—'; }
  function lossChart(history) {
    const valid = history.filter((row) => Number.isFinite(row.train_loss) && Number.isFinite(row.validation_loss));
    if (valid.length < 2) return null;
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 640 180'); svg.setAttribute('class', 'loss-chart');
    svg.setAttribute('preserveAspectRatio', 'none');
    svg.setAttribute('role', 'img'); svg.setAttribute('aria-label', 'Training and validation loss per epoch. Numeric data is available in the exported report.');
    const minimum = Math.min(...valid.map((row) => Math.min(row.train_loss, row.validation_loss)));
    const maximum = Math.max(...valid.map((row) => Math.max(row.train_loss, row.validation_loss)));
    const range = maximum - minimum || 1;
    for (const [field, color] of [['train_loss', '#86edcd'], ['validation_loss', '#8db6f8']]) {
      const line = document.createElementNS('http://www.w3.org/2000/svg', 'polyline');
      const points = valid.map((row, index) => (20 + index / (valid.length - 1) * 600).toFixed(2) + ',' + (158 - (row[field] - minimum) / range * 135).toFixed(2)).join(' ');
      line.setAttribute('points', points); line.setAttribute('stroke', color); line.setAttribute('stroke-width', '2'); line.setAttribute('fill', 'none');
      svg.append(line);
    }
    return svg;
  }
  function renderTraining(metrics, job) {
    $('training-empty').hidden = true;
    $('training-metrics').hidden = false;
    $('training-export').hidden = false;
    $('training-export').href = localArtifact(job, 'export');
    $('training-export').setAttribute('download', 'gnn-' + job.id.slice(0, 7) + '.zip');
    const content = document.createDocumentFragment();
    const cards = node('div', 'metrics-grid');
    for (const [key, label] of [['train', 'Train'], ['validation', 'Validation'], ['test', 'Test']]) cards.append(metric(label + ' · accuracy', percentage(metrics[key]?.accuracy), (metrics[key]?.samples ?? '—') + ' nodes · F1 ' + decimal(metrics[key]?.macro_f1)));
    content.append(cards);
    const history = metrics.training?.history || [];
    const chart = lossChart(history);
    if (chart) {
      const chartSection = node('div'); chartSection.append(node('p', 'chart-caption', 'Loss per epoch · mint: train · blue: validation'), chart);
      content.append(chartSection);
    }
    const rows = ['train', 'validation', 'test'].map((key) => [key, decimal(metrics[key]?.loss), percentage(metrics[key]?.accuracy), percentage(metrics.majority_baseline?.[key]?.accuracy)]);
    content.append(section('Majority baseline comparison', table(['Split', 'Loss', 'Accuracy', 'Baseline'], rows)));
    const training = metrics.training || {};
    content.append(section('Training', node('pre', 'detail-code', json({ model: metrics.model_type, epochs: training.epochs, best_epoch: training.best_epoch, initial_loss: training.initial_loss, final_loss: training.final_loss, device: training.device, seed: metrics.seed, dataset_hash: metrics.dataset_hash }))));
    content.append(section('Dataset & split audit', node('pre', 'detail-code', json({ splits: metrics.splits, dataset_audit: metrics.dataset_audit }))));
    if (metrics.limitations?.length) content.append(section('Declared limitations', node('pre', 'detail-code', metrics.limitations.join('\n'))));
    $('training-metrics').replaceChildren(content);
  }
  function renderDoctor(doctor) {
    const rows = [
      ['Python version', doctor.python],
      ['Native backend', doctor.backends?.native?.available],
      ['WebAssembly', doctor.backends?.wasm?.available],
      ['Ghidra', doctor.backends?.ghidra?.available],
      ['ILSpy / .NET', doctor.backends?.ilspy?.available],
      ['Console loaders · experimental', !!doctor.console_loaders?.profiles?.length],
      ['NSO · LZ4 decompression', doctor.console_loaders?.lz4_available],
      ['Type recovery · pyelftools', doctor.type_recovery?.available],
      ['GNN · bundled inference', doctor.gnn?.builtin_model_available],
      ['GNN · PyTorch training', doctor.gnn?.training_available],
      ...Object.entries(doctor.tools || {}).map(([key, value]) => [key, value || false]),
    ];
    const fragment = document.createDocumentFragment();
    for (const [label, value] of rows) {
      const row = node('div', 'doctor-row');
      const boolean = typeof value === 'boolean';
      const text = boolean ? value ? 'Available' : 'Unavailable' : safeText(value);
      row.append(node('span', 'doctor-name', label), node('span', 'doctor-value' + (boolean ? value ? ' available' : ' unavailable' : ''), text));
      fragment.append(row);
    }
    $('doctor-list').replaceChildren(fragment);
  }
  async function bootstrap(initial = true) {
    try {
      const data = await api('/api/bootstrap');
      state.token = data.token;
      state.providers = Array.isArray(data.providers) ? data.providers : [];
      state.jobs = Array.isArray(data.jobs) ? data.jobs : [];
      $('version').textContent = 'v' + safeText(data.version);
      renderDoctor(data.doctor || {});
      const setup = document.createDocumentFragment();
      for (const check of (data.readiness?.checks || []).slice(0, 8)) {
        const item = node('div', 'settings-note');
        const body = node('div');
        body.append(node('strong', '', check.label + ' · ' + check.status), node('p', '', check.next_step));
        item.append(body); setup.append(item);
      }
      $('readiness-list').replaceChildren(setup);
      renderJobs();
      if (initial) {
        providerChanged();
        restorePreferences();
        const latest = state.jobs.find((job) => job.status === 'SUCCEEDED' && (job.kind === 'analyze' || job.kind === 'demo'));
        if (latest) await openReport(latest, false);
      }
      updateRunButton();
      schedulePoll();
    } catch (error) { showError(error); schedulePoll(5000); }
  }

  document.querySelectorAll('[data-view]').forEach((item) => item.addEventListener('click', () => showView(item.dataset.view)));
  document.querySelectorAll('[data-go]').forEach((item) => item.addEventListener('click', () => showView(item.dataset.go)));
  window.addEventListener('hashchange', () => showView(window.location.hash.slice(1), false));
  $('menu-toggle').addEventListener('click', () => {
    const open = $('sidebar').classList.toggle('open');
    $('menu-toggle').setAttribute('aria-expanded', String(open));
  });
  document.addEventListener('click', (event) => { if ($('sidebar').classList.contains('open') && !$('sidebar').contains(event.target) && !$('menu-toggle').contains(event.target)) { $('sidebar').classList.remove('open'); $('menu-toggle').setAttribute('aria-expanded', 'false'); } });
  document.addEventListener('keydown', (event) => { if (event.key === 'Escape') { $('sidebar').classList.remove('open'); $('menu-toggle').setAttribute('aria-expanded', 'false'); } });
  $('dismiss-error').addEventListener('click', () => { $('error-banner').hidden = true; });
  $('binary-file').addEventListener('change', (event) => { const file = event.target.files[0]; if (file) selectBinary(file); });
  $('dropzone').addEventListener('keydown', (event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); $('binary-file').click(); } });
  for (const type of ['dragenter', 'dragover']) $('dropzone').addEventListener(type, (event) => { event.preventDefault(); $('dropzone').classList.add('dragging'); });
  for (const type of ['dragleave', 'drop']) $('dropzone').addEventListener(type, (event) => { event.preventDefault(); $('dropzone').classList.remove('dragging'); });
  $('dropzone').addEventListener('drop', (event) => { if (event.dataTransfer.files[0]) selectBinary(event.dataTransfer.files[0]); });
  window.addEventListener('dragover', (event) => { event.preventDefault(); });
  window.addEventListener('drop', (event) => { event.preventDefault(); });
  $('remove-file').addEventListener('click', clearBinary);
  $('gnn-model').addEventListener('change', () => { $('model-upload-field').hidden = $('gnn-model').value !== 'custom'; updateRunButton(); });
  $('console-profile').addEventListener('change', updateRunButton);
  $('model-file').addEventListener('change', (event) => { if (event.target.files[0]) selectAuxiliary(event.target.files[0], 'model'); });
  $('dataset-file').addEventListener('change', (event) => { if (event.target.files[0]) selectAuxiliary(event.target.files[0], 'dataset'); });
  const advancedAnalysis = document.querySelector('#analysis-form > details.advanced');
  if (advancedAnalysis) $('analysis-controls').append(advancedAnalysis);
  $('provider').addEventListener('change', providerChanged);
  $('llm-api-format').addEventListener('change', () => { updateApiCompatibility(); resetModelDiscovery(); });
  $('llm-url').addEventListener('input', () => { resetModelDiscovery(); updateProviderLocation(); });
  $('llm-key').addEventListener('input', resetModelDiscovery);
  $('test-llm-connection').addEventListener('click', () => discoverModels(true));
  $('refresh-llm-models').addEventListener('click', () => discoverModels(false));
  $('discovered-model-select').addEventListener('change', () => { if ($('discovered-model-select').value) $('llm-model').value = $('discovered-model-select').value; });
  $('save-preferences').addEventListener('click', savePreferences);
  $('clear-preferences').addEventListener('click', () => { try { localStorage.removeItem(preferenceKey); $('preferences-status').textContent = 'Saved preferences cleared. Current session settings are unchanged.'; } catch (error) { $('preferences-status').textContent = 'Browser storage is unavailable.'; } });
  document.querySelectorAll('.settings-nav a').forEach((link) => link.addEventListener('click', (event) => { event.preventDefault(); document.getElementById(link.getAttribute('href').slice(1))?.scrollIntoView({block:'start'}); }));
  $('analysis-form').addEventListener('submit', analyze);
  $('top-demo').addEventListener('click', demo);
  $('workspace-demo').addEventListener('click', demo);
  $('training-form').addEventListener('submit', train);
  $('training-kind').addEventListener('change', () => { const custom = $('training-kind').value === 'train_gnn'; $('dataset-field').hidden = !custom; $('samples-field').hidden = custom; });
  $('refresh-jobs').addEventListener('click', () => { if (!state.token) bootstrap(false); else poll(); });
  $('history-search').addEventListener('input', () => { state.jobLimit = 50; renderJobs(); });
  $('history-status').addEventListener('change', () => { state.jobLimit = 50; renderJobs(); });
  $('translation-language').addEventListener('change', updateTranslationControls);
  $('translate-function').addEventListener('click', translateFunction);
  $('translation-origin').addEventListener('click', () => {
    const job = state.jobs.find((entry) => entry.id === state.report?.translation?.source_job_id && entry.status === 'SUCCEEDED');
    if (job) openReport(job);
  });
  $('provider').addEventListener('change', updateTranslationControls);
  $('refresh-doctor').addEventListener('click', () => bootstrap(false));
  $('configure-provider').addEventListener('click', () => { showView('workspace'); $('provider').focus(); $('provider').scrollIntoView({ block: 'center' }); });
  $('function-search').addEventListener('input', () => { state.functionLimit = 80; renderFunctions(); });
  $('function-more').addEventListener('click', () => { state.functionLimit += 80; renderFunctions(); });
  $('type-search').addEventListener('input', () => { state.typeLimit = 100; renderTypes(); });
  $('type-more').addEventListener('click', () => { state.typeLimit += 100; renderTypes(); });
  document.querySelectorAll('[data-code]').forEach((tab) => {
    tab.addEventListener('click', () => { state.codeTab = tab.dataset.code; renderCode(); });
    tab.addEventListener('keydown', (event) => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
      event.preventDefault();
      const tabs = [...document.querySelectorAll('[data-code]')];
      const index = tabs.indexOf(tab);
      const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : (index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
      state.codeTab = tabs[next].dataset.code;
      renderCode(); tabs[next].focus();
    });
  });
  $('copy-code').addEventListener('click', async () => {
    try { await navigator.clipboard.writeText($('code-output').textContent); toast('Content copied.'); }
    catch (error) { const range = document.createRange(); range.selectNodeContents($('code-output')); const selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range); toast('Content selected. Use Ctrl+C or Cmd+C to copy.'); }
  });
  window.addEventListener('pagehide', () => { $('llm-key').value = ''; clearTimeout(pollTimer); });
  showView(window.location.hash.slice(1) || 'workspace', false);
  bootstrap();
})();
