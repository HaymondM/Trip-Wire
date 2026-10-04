// Side panel: injects the content script into the active tab, runs the
// extracted text through the Go/WASM engine, and renders the report.
// All page-derived text is untrusted and is only ever set via textContent.

const statusEl = document.getElementById('status');
const controlsEl = document.getElementById('controls');
const findingsEl = document.getElementById('findings');
const rescanBtn = document.getElementById('rescan');
const agentViewToggle = document.getElementById('agent-view');

let current = null; // { tabId, report }

// Bumped by every new scan and every tab switch or navigation. A scan whose
// generation is no longer current finished too late and must not touch the UI.
let generation = 0;
let scanningTabId = null;

const engineReady = (async () => {
  const go = new Go();
  const { instance } = await WebAssembly.instantiateStreaming(fetch('engine.wasm'), go.importObject);
  go.run(instance);
})();

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  if (text !== undefined) {
    node.textContent = text;
  }
  return node;
}

function showMessage(text) {
  statusEl.replaceChildren(el('p', 'muted', text));
  controlsEl.hidden = true;
  findingsEl.replaceChildren();
}

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

function invalidate(message) {
  generation++;
  scanningTabId = null;
  current = null;
  showMessage(message);
}

async function scan() {
  const myGeneration = ++generation;
  const isStale = () => myGeneration !== generation;
  agentViewToggle.checked = false;
  try {
    const tab = await activeTab();
    if (isStale()) {
      return;
    }
    if (!tab?.id) {
      showMessage('No active tab to scan.');
      return;
    }
    scanningTabId = tab.id;
    showMessage('Scanning…');
    try {
      await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ['content.js'] });
    } catch {
      if (!isStale()) {
        current = null;
        showMessage('Trip Wire only reads pages you ask it to. Click the Trip Wire toolbar icon on this tab to scan it.');
      }
      return;
    }
    const page = await chrome.tabs.sendMessage(tab.id, { type: 'trip-wire:extract' });
    await engineReady;
    const report = JSON.parse(globalThis.tripWireAnalyze(JSON.stringify(page.segments)));
    const latestTab = await activeTab();
    if (isStale() || latestTab?.id !== tab.id) {
      return;
    }
    if (report.error) {
      showMessage(`Engine error: ${report.error}`);
      return;
    }
    current = { tabId: tab.id, report };
    render(page, report);
  } catch (err) {
    if (!isStale()) {
      showMessage(`Scan failed: ${err.message}`);
    }
  } finally {
    if (!isStale()) {
      scanningTabId = null;
    }
  }
}

function render(page, report) {
  // A partial scan must never present itself as clean.
  const verdict = page.truncated && report.verdict === 'clean' ? 'incomplete' : report.verdict;
  const score = el('div', `score ${verdict}`);
  score.append(el('span', 'number', String(report.score)));
  const summary = el('div');
  summary.append(
    el('div', 'verdict', verdict),
    el('div', null, `${report.findings.length} finding${report.findings.length === 1 ? '' : 's'} · ${report.stats.hiddenSegments} hidden of ${report.stats.segmentsScanned} text segments`),
  );
  score.append(summary);
  const children = [score];
  if (page.truncated) {
    children.push(el('p', 'warning', `Partial scan: this page is very large and ${page.droppedSegments} text segment${page.droppedSegments === 1 ? ' was' : 's were'} skipped. Hidden text, comments, and attributes were prioritized.`));
  }
  children.push(el('p', 'page-title', page.title || page.url));
  statusEl.replaceChildren(...children);

  controlsEl.hidden = false;
  agentViewToggle.disabled = report.findings.length === 0;

  if (report.findings.length === 0) {
    const emptyMessage = page.truncated
      ? 'No hidden instructions found in the part of the page that was scanned.'
      : 'No hidden instructions found on this page.';
    findingsEl.replaceChildren(el('li', 'muted', emptyMessage));
    return;
  }

  findingsEl.replaceChildren(...report.findings.map(renderFinding));
}

function renderFinding(finding) {
  const item = el('li');
  const button = el('button', `finding ${finding.severity}`);
  button.type = 'button';
  button.title = 'Show this on the page';
  button.append(el('span', 'severity', finding.severity), el('span', 'message', finding.message));
  if (finding.decoded) {
    button.append(el('span', 'decoded-label', 'Decoded hidden text'), el('span', 'excerpt', finding.decoded));
  } else if (finding.excerpt) {
    button.append(el('span', 'excerpt', finding.excerpt));
  }
  button.addEventListener('click', async () => {
    if (!current) {
      return;
    }
    if (!agentViewToggle.checked) {
      agentViewToggle.checked = true;
      await setAgentView(true);
    }
    chrome.tabs.sendMessage(current.tabId, { type: 'trip-wire:focus', segmentId: finding.segmentId });
  });
  item.append(button);
  return item;
}

async function setAgentView(on) {
  if (!current) {
    return;
  }
  const message = on
    ? { type: 'trip-wire:reveal', findings: current.report.findings }
    : { type: 'trip-wire:clear' };
  await chrome.tabs.sendMessage(current.tabId, message);
}

rescanBtn.addEventListener('click', scan);
agentViewToggle.addEventListener('change', () => setAgentView(agentViewToggle.checked));

chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type === 'trip-wire:scan') {
    scan();
  }
});

chrome.tabs.onActivated.addListener(() => {
  invalidate('Switched tabs. Click the Trip Wire toolbar icon to scan this page.');
});

chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (info.status === 'loading' && (current?.tabId === tabId || scanningTabId === tabId)) {
    invalidate('Page changed. Click the Trip Wire toolbar icon to scan it again.');
  }
});

scan();
