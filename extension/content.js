// Injected on demand via activeTab. Collects every piece of text an AI agent
// might read from the page, tagged with the reasons a human can't see it, and
// can reveal flagged text in place ("agent view").
(() => {
  if (window.__finePrint) {
    return;
  }

  const SKIP_SELECTOR = 'script, style, noscript, template, svg, head';
  const ATTRIBUTES = ['aria-label', 'alt', 'title'];
  const META_KEYS = /description|title|keywords|^og:|^twitter:|^ai[-_:]|robots/;
  const OWN_ATTR = 'data-fine-print';
  const MAX_SEGMENTS = 20000;
  const MAX_CALLOUT_CHARS = 800;
  const COLOR_MATCH_DISTANCE = 24;

  const truncate = (text, max) => (text.length > max ? `${text.slice(0, max)}…` : text);

  let segmentNodes = new Map();
  let hiddenCache = new WeakMap();
  let blockCache = new WeakMap();

  // ---------- visibility ----------

  function parseColor(value) {
    const m = /rgba?\(([^)]+)\)/.exec(value || '');
    if (!m) {
      return null;
    }
    const [r, g, b, a = 1] = m[1].split(/[\s,/]+/).filter(Boolean).map(Number);
    return { r, g, b, a };
  }

  function colorDistance(x, y) {
    return Math.hypot(x.r - y.r, x.g - y.g, x.b - y.b);
  }

  function effectiveBackground(el) {
    for (let node = el; node instanceof Element; node = node.parentElement) {
      const style = getComputedStyle(node);
      if (style.backgroundImage && style.backgroundImage !== 'none') {
        return null; // text over an image: can't judge contrast reliably
      }
      const bg = parseColor(style.backgroundColor);
      if (bg && bg.a > 0.5) {
        return bg;
      }
    }
    return { r: 255, g: 255, b: 255, a: 1 };
  }

  // Reasons an element, and therefore everything inside it, is invisible.
  function containerReasons(el) {
    if (!(el instanceof Element)) {
      return [];
    }
    if (hiddenCache.has(el)) {
      return hiddenCache.get(el);
    }
    const reasons = new Set(containerReasons(el.parentElement));
    const style = getComputedStyle(el);

    if (style.display === 'none') {
      reasons.add('display-none');
    }
    if (parseFloat(style.opacity) < 0.05) {
      reasons.add('transparent');
    }
    if (style.clip === 'rect(0px, 0px, 0px, 0px)' || /inset\((50|100)%/.test(style.clipPath)) {
      reasons.add('clipped');
    }
    if (style.display !== 'none') {
      const rect = el.getBoundingClientRect();
      const clipsOverflow = /hidden|clip/.test(style.overflow);
      if (clipsOverflow && (rect.width <= 1 || rect.height <= 1)) {
        reasons.add('zero-size');
      }
      const left = rect.left + window.scrollX;
      const top = rect.top + window.scrollY;
      if (rect.width > 0 && (left + rect.width < 0 || top + rect.height < 0 || left > document.documentElement.clientWidth + 1000)) {
        reasons.add('offscreen');
      }
    }

    const result = [...reasons];
    hiddenCache.set(el, result);
    return result;
  }

  // Reasons the text directly inside el is invisible.
  function textReasons(el) {
    const reasons = new Set(containerReasons(el));
    const style = getComputedStyle(el);
    if (style.visibility === 'hidden' || style.visibility === 'collapse') {
      reasons.add('visibility-hidden');
    }
    if (parseFloat(style.fontSize) < 2) {
      reasons.add('tiny-font');
    }
    if (parseFloat(style.textIndent) <= -999) {
      reasons.add('offscreen');
    }
    const fg = parseColor(style.color);
    if (fg && fg.a < 0.05) {
      reasons.add('transparent-text');
    } else if (fg) {
      const bg = effectiveBackground(el);
      if (bg && colorDistance(fg, bg) < COLOR_MATCH_DISTANCE) {
        reasons.add('color-matches-background');
      }
    }
    return [...reasons].sort();
  }

  // Nearest ancestor that isn't inline, so "ignore <b>previous</b> instructions"
  // stays one segment instead of three.
  function blockOf(el) {
    if (blockCache.has(el)) {
      return blockCache.get(el);
    }
    let block = el;
    while (block.parentElement && block !== document.body) {
      const display = getComputedStyle(block).display;
      if (!display.startsWith('inline') && display !== 'contents') {
        break;
      }
      block = block.parentElement;
    }
    blockCache.set(el, block);
    return block;
  }

  // ---------- extraction ----------

  function extract() {
    clearReveal();
    segmentNodes = new Map();
    hiddenCache = new WeakMap();
    blockCache = new WeakMap();
    const segments = [];

    const add = (anchor, element, text, source, hiddenReasons) => {
      const normalized = text.replace(/[ \t\n\r\f]+/g, ' ').trim();
      if (!normalized || segments.length >= MAX_SEGMENTS) {
        return;
      }
      const id = segments.length;
      segmentNodes.set(id, { anchor, element, source, text: normalized });
      segments.push({ id, text: normalized, source, tag: element ? element.tagName : '', hiddenReasons });
    };

    let group = null;
    const flush = () => {
      if (group) {
        add(group.anchor, group.block, group.text, 'text', group.reasons);
        group = null;
      }
    };

    const walker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_COMMENT);
    const reasonsByParent = new Map();
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      const parent = node.parentElement;
      if (!parent || parent.closest(`[${OWN_ATTR}]`)) {
        continue;
      }
      if (node.nodeType === Node.COMMENT_NODE) {
        flush();
        add(node, parent, node.data, 'comment', ['html-comment']);
        continue;
      }
      if (parent.closest(SKIP_SELECTOR) || !node.data.trim()) {
        continue;
      }
      if (!reasonsByParent.has(parent)) {
        reasonsByParent.set(parent, textReasons(parent));
      }
      const reasons = reasonsByParent.get(parent);
      const block = blockOf(parent);
      const key = reasons.join(',');
      if (group && group.block === block && group.key === key) {
        group.text += node.data;
      } else {
        flush();
        group = { anchor: parent, block, key, reasons, text: node.data };
      }
    }
    flush();

    const attrSelector = ATTRIBUTES.map((a) => `[${a}]`).join(',');
    for (const el of document.body.querySelectorAll(attrSelector)) {
      if (el.closest(`[${OWN_ATTR}]`)) {
        continue;
      }
      for (const attr of ATTRIBUTES) {
        const value = el.getAttribute(attr);
        if (value) {
          add(el, el, value, `attr:${attr}`, ['attribute']);
        }
      }
    }

    for (const meta of document.querySelectorAll('meta[content]')) {
      const key = (meta.getAttribute('name') || meta.getAttribute('property') || '').toLowerCase();
      if (META_KEYS.test(key)) {
        add(meta, null, meta.content, 'meta', ['meta-tag']);
      }
    }

    return { url: location.href, title: document.title, segments };
  }

  // ---------- agent view ----------

  const CALLOUT_CSS = `
    :host { all: initial; display: block; margin: 6px 0; }
    .box { font: 13px/1.45 system-ui, -apple-system, sans-serif; color: #fff; background: #b42318;
           border: 2px solid #7a1a12; border-radius: 6px; padding: 8px 10px; box-shadow: 0 2px 8px rgba(0,0,0,.25); }
    .box.medium { background: #b54708; border-color: #7a2e0e; }
    .box.low { background: #475467; border-color: #344054; }
    .label { font-weight: 700; letter-spacing: .02em; text-transform: uppercase; font-size: 11px; opacity: .9; }
    .text { margin-top: 4px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; white-space: pre-wrap; word-break: break-word; }
  `;

  // The outermost hidden ancestor, so the callout lands somewhere visible.
  function visibleAnchor(el) {
    let anchor = el;
    while (anchor.parentElement && anchor.parentElement !== document.body && containerReasons(anchor.parentElement).length > 0) {
      anchor = anchor.parentElement;
    }
    return anchor;
  }

  function buildCallout(finding, fullText) {
    const host = document.createElement('div');
    host.setAttribute(OWN_ATTR, 'callout');
    host.dataset.segmentId = String(finding.segmentId);
    const shadow = host.attachShadow({ mode: 'open' });
    const style = document.createElement('style');
    style.textContent = CALLOUT_CSS;
    const box = document.createElement('div');
    box.className = `box ${finding.severity}`;
    const label = document.createElement('div');
    label.className = 'label';
    label.textContent = `Fine Print · hidden from you, read by AI`;
    const message = document.createElement('div');
    message.textContent = finding.message;
    const text = document.createElement('div');
    text.className = 'text';
    text.textContent = finding.decoded ? `Decoded: ${finding.decoded}` : truncate(fullText, MAX_CALLOUT_CHARS);
    box.append(label, message, text);
    shadow.append(style, box);
    return host;
  }

  function reveal(findings) {
    clearReveal();
    const seen = new Set();
    for (const finding of findings) {
      if (seen.has(finding.segmentId)) {
        continue;
      }
      seen.add(finding.segmentId);
      const entry = segmentNodes.get(finding.segmentId);
      if (!entry) {
        continue;
      }
      const callout = buildCallout(finding, entry.text);
      if (entry.source === 'meta' || !entry.element || entry.element === document.body || !document.body.contains(entry.anchor)) {
        document.body.prepend(callout);
      } else if (entry.source === 'comment') {
        entry.anchor.parentNode.insertBefore(callout, entry.anchor);
      } else {
        const target = visibleAnchor(entry.element);
        target.parentNode.insertBefore(callout, target);
      }
    }
  }

  function clearReveal() {
    for (const el of document.querySelectorAll(`[${OWN_ATTR}="callout"]`)) {
      el.remove();
    }
  }

  function focus(segmentId) {
    const callout = document.querySelector(`[${OWN_ATTR}="callout"][data-segment-id="${Number(segmentId)}"]`);
    callout?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  window.__finePrint = { extract, reveal, clearReveal, focus };

  if (!globalThis.chrome?.runtime?.onMessage) {
    return; // loaded outside the extension (test harness)
  }
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    switch (msg?.type) {
      case 'fine-print:extract':
        sendResponse(extract());
        break;
      case 'fine-print:reveal':
        reveal(msg.findings || []);
        sendResponse({ ok: true });
        break;
      case 'fine-print:clear':
        clearReveal();
        sendResponse({ ok: true });
        break;
      case 'fine-print:focus':
        focus(msg.segmentId);
        sendResponse({ ok: true });
        break;
    }
  });
})();
