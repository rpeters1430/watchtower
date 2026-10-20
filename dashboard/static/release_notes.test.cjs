const test = require('node:test');
const assert = require('node:assert/strict');
const { parseInlineMarkdown, parseMarkdown, shouldShowReleaseNotes, dismissReleaseNotes, DISMISSAL_KEY } = require('./release_notes.js');

function storage(initial = null) {
  let value = initial;
  return { getItem: () => value, setItem: (_key, next) => { value = next; } };
}

test('renders common changelog Markdown without treating HTML as markup', () => {
  assert.deepEqual(parseMarkdown('## Fixes\n- Faster checks\n\n<script>alert("x")</script>'), [
    { type: 'heading', level: 2, text: 'Fixes' },
    { type: 'list', items: ['Faster checks'] },
    { type: 'paragraph', text: '<script>alert("x")</script>' },
  ]);
  const parts = parseInlineMarkdown('[Docs](https://example.com) **bold** `code`');
  assert.equal(parts[0].type, 'link');
  assert.equal(parts[1].type, 'text');
  assert.equal(parts[2].type, 'strong');
  assert.equal(parts[3].type, 'text');
  assert.equal(parts[4].type, 'code');
  assert.equal(parseInlineMarkdown('[bad](javascript:alert)')[0].type, 'text');
});

test('suppresses a dismissed revision and shows a different revision', () => {
  const store = storage();
  const release = { version: '1.0.0', revision: 'abc123', notes: '## Changes' };
  assert.equal(shouldShowReleaseNotes(release, store), true);
  assert.equal(shouldShowReleaseNotes({ ...release, notes: '' }, store), false);
  dismissReleaseNotes(release.revision, store);
  assert.equal(store.getItem(DISMISSAL_KEY), 'abc123');
  assert.equal(shouldShowReleaseNotes(release, store), false);
  assert.equal(shouldShowReleaseNotes({ ...release, revision: 'def456' }, store), true);
});
