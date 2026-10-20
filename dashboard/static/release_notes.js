(function attachReleaseNotes(global, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (global) global.WatchtowerReleaseNotes = api;
})(typeof globalThis === 'undefined' ? this : globalThis, function releaseNotesModule() {
  const DISMISSAL_KEY = 'watchtower-dashboard.dismissed-release-revision';

  function storage() {
    try { return globalThis.localStorage; } catch { return undefined; }
  }

  function parseInlineMarkdown(text) {
    const parts = [];
    const pattern = /\[([^\]]+)\]\(([^)]+)\)|\*\*([^*]+)\*\*|`([^`]+)`/g;
    let offset = 0;
    let match;
    while ((match = pattern.exec(text))) {
      if (match.index > offset) parts.push({ type: 'text', text: text.slice(offset, match.index) });
      if (match[1] !== undefined) {
        let parsed;
        try { parsed = new URL(match[2]); } catch { parsed = null; }
        if (parsed && ['http:', 'https:'].includes(parsed.protocol)) parts.push({ type: 'link', text: match[1], url: parsed.href });
        else parts.push({ type: 'text', text: match[0] });
      } else if (match[3] !== undefined) parts.push({ type: 'strong', text: match[3] });
      else parts.push({ type: 'code', text: match[4] });
      offset = pattern.lastIndex;
    }
    if (offset < text.length) parts.push({ type: 'text', text: text.slice(offset) });
    return parts;
  }

  function parseMarkdown(markdown) {
    const blocks = [];
    let paragraph = [];
    let items = [];
    const flushParagraph = () => { if (paragraph.length) blocks.push({ type: 'paragraph', text: paragraph.join(' ') }); paragraph = []; };
    const flushItems = () => { if (items.length) blocks.push({ type: 'list', items }); items = []; };
    for (const line of String(markdown || '').split(/\r?\n/)) {
      const trimmed = line.trim();
      const heading = /^(#{1,3})\s+(.+)$/.exec(trimmed);
      const item = /^[-*]\s+(.+)$/.exec(trimmed);
      if (!trimmed) { flushParagraph(); flushItems(); }
      else if (heading) { flushParagraph(); flushItems(); blocks.push({ type: 'heading', level: heading[1].length, text: heading[2] }); }
      else if (item) { flushParagraph(); items.push(item[1]); }
      else { flushItems(); paragraph.push(trimmed); }
    }
    flushParagraph(); flushItems();
    return blocks;
  }

  function appendInline(parent, text) {
    for (const part of parseInlineMarkdown(text)) {
      if (part.type === 'text') parent.appendChild(document.createTextNode(part.text));
      else if (part.type === 'link') {
        const link = document.createElement('a');
        link.href = part.url;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        link.textContent = part.text;
        parent.appendChild(link);
      } else {
        const node = document.createElement(part.type === 'strong' ? 'strong' : 'code');
        node.textContent = part.text;
        parent.appendChild(node);
      }
    }
  }

  function renderMarkdown(container, markdown) {
    for (const block of parseMarkdown(markdown)) {
      let node;
      if (block.type === 'heading') node = document.createElement(`h${block.level + 1}`);
      else if (block.type === 'list') {
        node = document.createElement('ul');
        for (const value of block.items) {
          const li = document.createElement('li');
          appendInline(li, value);
          node.appendChild(li);
        }
      } else {
        node = document.createElement('p');
        appendInline(node, block.text);
      }
      if (block.type === 'heading') appendInline(node, block.text);
      container.appendChild(node);
    }
  }

  function shouldShowReleaseNotes(metadata, store = storage()) {
    if (!metadata || typeof metadata.revision !== 'string' || !metadata.revision.trim()) return false;
    if (typeof metadata.notes !== 'string' || !metadata.notes.trim()) return false;
    try { return store?.getItem(DISMISSAL_KEY) !== metadata.revision; } catch { return true; }
  }

  function dismissReleaseNotes(revision, store = storage()) {
    try { store?.setItem(DISMISSAL_KEY, revision); } catch { /* storage may be disabled */ }
  }

  function loadReleaseNotes() {
    fetch('/api/release-notes', { credentials: 'same-origin', cache: 'no-store' })
      .then((response) => response.ok ? response.json() : null)
      .then((metadata) => {
        if (!shouldShowReleaseNotes(metadata)) return;
        const dialog = document.getElementById('release-notes-dialog');
        const content = document.getElementById('release-notes-content');
        const close = document.getElementById('release-notes-close');
        if (!dialog || !content || !close) return;
        document.getElementById('release-notes-title').textContent = `What’s new${metadata.version ? ` in ${metadata.version}` : ''}`;
        document.getElementById('release-notes-revision').textContent = `Revision ${metadata.revision}`;
        renderMarkdown(content, metadata.notes);
        const dismiss = () => { dismissReleaseNotes(metadata.revision); if (dialog.open) dialog.close(); };
        close.onclick = dismiss;
        dialog.oncancel = (event) => { event.preventDefault(); dismiss(); };
        dialog.showModal();
        close.focus();
      })
      .catch(() => {});
  }

  return { DISMISSAL_KEY, parseInlineMarkdown, parseMarkdown, renderMarkdown, shouldShowReleaseNotes, dismissReleaseNotes, loadReleaseNotes };
});
