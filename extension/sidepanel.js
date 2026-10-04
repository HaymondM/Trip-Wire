// Side panel: injects the content script into the active tab, runs the
// extracted text through the Go/WASM engine, and renders the report.
// All page-derived text is untrusted and is only ever set via textContent.

const statusEl = document.getElementById('status');
const controlsEl = document.getElementById('controls');
const findingsEl = document.getElementById('findings');
const rescanBtn = document.getElementById('rescan');
const agentViewToggle = document.getElementById('agent-view');

let current = null; // { tabId, report }
let scanning = false;

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

async function scan() {
  if (scanning) {
    return;
  }
  scanning = true;
  agentViewToggle.checked = false;
  try {
    const tab = await activeTab();
    if (!tab?.id) {
      showMessage('No active tab to scan.');
      return;
    }
    showMessage('Scanning…');
    try {
      await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ['content.js'] });
    } catch {
      current = null;
      showMessage('Fine Print only reads pages you ask it to. Click the Fine Print toolbar icon on this tab to scan it.');
      return;
    }
    const page = await chrome.tabs.sendMessage(tab.id, { type: 'fine-print:extract' });
    await engineReady;
    const report = JSON.parse(globalThis.finePrintAnalyze(JSON.stringify(page.segments)));
    if (report.error) {
      showMessage(`Engine error: ${report.error}`);
      return;
    }
    current = { tabId: tab.id, report };
    render(page, report);
  } catch (err) {
    showMessage(`Scan failed: ${err.message}`);
  } finally {
    scanning = false;
  }
}

function render(page, report) {
  const score = el('div', `score ${report.verdict}`);
  score.append(el('span', 'number', String(report.score)));
  const summary = el('div');
  summary.append(
    el('div', 'verdict', report.verdict),
    el('div', null, `${report.findings.length} finding${report.findings.length === 1 ? '' : 's'} · ${report.stats.hiddenSegments} hidden of ${report.stats.segmentsScanned} text segments`),
  );
  score.append(summary);
  statusEl.replaceChildren(score, el('p', 'page-title', page.title || page.url));

  controlsEl.hidden = false;
  agentViewToggle.disabled = report.findings.length === 0;

  if (report.findings.length === 0) {
    findingsEl.replaceChildren(el('li', 'muted', 'No hidden instructions found on this page.'));
    return;
  }

  findingsEl.replaceChildren(...report.findings.map(renderFinding));
}

function renderFinding(finding) {
  const item = el('li', `finding ${finding.severity}`);
  item.append(el('span', 'severity', finding.severity), el('p', null, finding.message));
  if (finding.decoded) {
    item.append(el('div', 'decoded-label', 'Decoded hidden text'), el('div', 'excerpt', finding.decoded));
  } else if (finding.excerpt) {
    item.append(el('div', 'excerpt', finding.excerpt));
  }
  item.addEventListener('click', async () => {
    if (!current) {
      return;
    }
    if (!agentViewToggle.checked) {
      agentViewToggle.checked = true;
      await setAgentView(true);
    }
    chrome.tabs.sendMessage(current.tabId, { type: 'fine-print:focus', segmentId: finding.segmentId });
  });
  return item;
}

async function setAgentView(on) {
  if (!current) {
    return;
  }
  const message = on
    ? { type: 'fine-print:reveal', findings: current.report.findings }
    : { type: 'fine-print:clear' };
  await chrome.tabs.sendMessage(current.tabId, message);
}

rescanBtn.addEventListener('click', scan);
agentViewToggle.addEventListener('change', () => setAgentView(agentViewToggle.checked));

chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type === 'fine-print:scan') {
    scan();
  }
});

chrome.tabs.onActivated.addListener(() => {
  current = null;
  showMessage('Switched tabs. Click the Fine Print toolbar icon to scan this page.');
});

chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (current?.tabId === tabId && info.status === 'loading') {
    current = null;
    showMessage('Page changed. Click the Fine Print toolbar icon to scan it again.');
  }
});

scan();
