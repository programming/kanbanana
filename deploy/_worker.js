// Cloudflare Pages Worker for Kanbanana
// - Auth via password (stored as secret)
// - Board data persisted in Workers KV
// - Serves the full SPA

const KV_KEY = 'board-data';
const VERSION_KEY = 'board-version';
const HISTORY_KEY = 'board-history';
const PASSWORD_KEY = 'password-hash';
const MAX_VERSIONS = 10;

// Default board data
const DEFAULT_DATA = {
  columns: [
    { id: 'col-1', title: 'To Do', color: '#e2e8f0', cards: [] },
    { id: 'col-2', title: 'In Progress', color: '#fde68a', cards: [] },
    { id: 'col-3', title: 'Done', color: '#a7f3d0', cards: [] }
  ]
};

// ─── Crypto helpers ───────────────────────────────────────────────

async function hashPassword(pw) {
  const enc = new TextEncoder().encode(pw);
  const hash = await crypto.subtle.digest('SHA-256', enc);
  return btoa(String.fromCharCode(...new Uint8Array(hash)));
}

async function signCookie(value, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(value));
  return value + '.' + btoa(String.fromCharCode(...new Uint8Array(sig)));
}

async function verifyCookie(cookie, secret) {
  if (!cookie) return false;
  const parts = cookie.split('.');
  if (parts.length !== 2) return false;
  const [value, sigB64] = parts;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const sig = Uint8Array.from(atob(sigB64), c => c.charCodeAt(0));
  return crypto.subtle.verify('HMAC', key, sig, enc.encode(value));
}

function parseCookies(request) {
  const header = request.headers.get('Cookie') || '';
  const map = {};
  header.split(';').forEach(c => {
    const [k, ...v] = c.trim().split('=');
    if (k) map[k] = v.join('=');
  });
  return map;
}

// ─── Auth middleware ──────────────────────────────────────────────

async function isAuthed(request, env) {
  const cookies = parseCookies(request);
  return verifyCookie(cookies.auth, env.COOKIE_SECRET);
}

// ─── HTML pages ───────────────────────────────────────────────────

const LOGIN_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Kanbanana - Login</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f0f2f5;display:flex;align-items:center;justify-content:center;min-height:100vh}
.login-box{background:#fff;padding:40px;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.1);width:360px;max-width:90vw}
h1{font-size:24px;margin-bottom:8px;text-align:center}
h1 span{color:#4f46e5}
p{color:#6b7280;font-size:14px;text-align:center;margin-bottom:24px}
input{width:100%;padding:10px 14px;border:1px solid #d1d5db;border-radius:8px;font-size:15px;outline:none;margin-bottom:16px}
input:focus{border-color:#4f46e5;box-shadow:0 0 0 3px #4f46e520}
button{width:100%;padding:10px;background:#4f46e5;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer}
button:hover{background:#4338ca}
.error{color:#ef4444;font-size:13px;text-align:center;margin-top:8px;display:none}
</style>
</head>
<body>
<div class="login-box">
  <h1>🍌 <span>Kanbanana</span></h1>
  <p>Enter password to continue</p>
  <form method="post" action="/login">
    <input type="password" name="password" placeholder="Password" autofocus required>
    <button type="submit">Sign In</button>
  </form>
  <div class="error" id="error">{{ERROR}}</div>
</div>
<script>
  const params = new URLSearchParams(window.location.search);
  if (params.get('e') === '1') document.getElementById('error').style.display = 'block';
</script>
</body>
</html>`;

// The kanban board HTML — same as index.html but with fetch instead of localStorage
const KANBAN_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Kanbanana</title>
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg: #f0f2f5;
  --col-bg: #e4e7ec;
  --card-bg: #fff;
  --text: #1a1a2e;
  --text-secondary: #6b7280;
  --accent: #4f46e5;
  --accent-hover: #4338ca;
  --danger: #ef4444;
  --danger-hover: #dc2626;
  --border: #d1d5db;
  --shadow: 0 1px 3px rgba(0,0,0,.1);
  --shadow-lg: 0 4px 14px rgba(0,0,0,.12);
  --radius: 10px;
  --radius-sm: 6px;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
}

/* ─── Header ─── */
.header {
  background: #fff;
  border-bottom: 1px solid var(--border);
  padding: 14px 24px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  flex-wrap: wrap;
  position: sticky;
  top: 0;
  z-index: 100;
  box-shadow: var(--shadow);
}
.header h1 { font-size: 22px; font-weight: 700; letter-spacing: -.3px; display: flex; align-items: center; gap: 8px; }
.header h1 span { color: var(--accent); }
.header-actions { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }

/* ─── Buttons ─── */
.btn {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 8px 16px; border-radius: var(--radius-sm);
  font-size: 14px; font-weight: 500; cursor: pointer;
  border: 1px solid transparent; transition: all .15s ease;
  white-space: nowrap;
}
.btn-primary { background: var(--accent); color: #fff; border-color: var(--accent); }
.btn-primary:hover { background: var(--accent-hover); }
.btn-outline { background: #fff; color: var(--text); border-color: var(--border); }
.btn-outline:hover { background: #f9fafb; }
.btn-ghost { background: transparent; border-color: transparent; color: var(--text-secondary); padding: 6px 8px; }
.btn-ghost:hover { background: #f3f4f6; color: var(--text); }
.btn-danger { background: var(--danger); color: #fff; }
.btn-danger:hover { background: var(--danger-hover); }
.btn-sm { padding: 4px 10px; font-size: 12px; }
.btn-icon { padding: 6px; border-radius: 50%; line-height: 1; }

/* ─── Board ─── */
.board {
  display: flex;
  gap: 20px;
  padding: 20px 24px;
  align-items: flex-start;
  height: calc(100vh - 120px);
  overflow-x: auto;
  overflow-y: hidden;
}
.board::-webkit-scrollbar { height: 6px; }
.board::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 3px; }

/* ─── Column ─── */
.column {
  background: var(--col-bg);
  border-radius: var(--radius);
  flex: 1 1 0;
  min-width: 220px;
  display: flex;
  flex-direction: column;
  max-height: calc(100vh - 150px);
  box-shadow: var(--shadow);
  transition: box-shadow .2s;
}
.column.drag-over { box-shadow: 0 0 0 2px var(--accent), var(--shadow-lg); }

.column-header { padding: 14px 16px 10px; display: flex; flex-direction: column; gap: 6px; border-radius: var(--radius) var(--radius) 0 0; }
.column-title-wrap { display: flex; align-items: center; gap: 8px; flex: 1; min-width: 0; }
.column-dot { display: none; }
.column-title { font-weight: 600; font-size: 14px; border: 2px solid transparent; padding: 2px 6px; border-radius: 4px; background: transparent; outline: none; cursor: text; color: #1e293b; }
.column-header .btn-ghost { color: #475569; }
.column-header .btn-ghost:hover { background: rgba(0,0,0,.06); color: #1e293b; }
.column-count { font-size: 12px; color: #475569; background: rgba(0,0,0,.07); padding: 2px 8px; border-radius: 10px; font-weight: 600; }

/* ─── Card list ─── */
.card-list { flex: 1; overflow-y: auto; padding: 4px 12px 12px; min-height: 60px; display: flex; flex-direction: column; gap: 8px; }
.card-list:empty::after { content: 'Drop cards here'; display: flex; align-items: center; justify-content: center; color: #9ca3af; font-size: 13px; height: 80px; border: 2px dashed #cbd5e1; border-radius: var(--radius-sm); }

/* ─── Card ─── */
.card { background: var(--card-bg); border-radius: var(--radius-sm); padding: 12px 14px; box-shadow: var(--shadow); cursor: grab; transition: transform .15s, box-shadow .15s; position: relative; user-select: none; }
.card:hover { box-shadow: var(--shadow-lg); }
.card:active { cursor: grabbing; }
.card.dragging { opacity: .5; transform: rotate(1deg); }
.card.drag-target { box-shadow: 0 0 0 2px var(--accent); }
.card-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 6px; }
.card-content { font-size: 14px; line-height: 1.45; outline: none; border-radius: 4px; padding: 2px 4px; margin: 0 -4px; word-break: break-word; white-space: pre-wrap; }
.card-content:focus { background: #f9fafb; }
.card-content:empty::before { content: 'Click to add content'; color: #cbd5e1; }
.card-meta { display: flex; align-items: center; gap: 8px; margin-top: 8px; flex-wrap: wrap; }
.card-date { font-size: 11px; color: var(--text-secondary); display: flex; align-items: center; gap: 4px; }
.card-actions { display: flex; gap: 2px; opacity: 0; transition: opacity .15s; justify-content: flex-end; margin-top: 6px; }
.card:hover .card-actions { opacity: 1; }

/* ─── Color picker ─── */
.color-picker { display: flex; gap: 4px; padding: 2px; }
.color-option { width: 18px; height: 18px; border-radius: 50%; cursor: pointer; border: 2px solid transparent; transition: transform .15s; }
.color-option:hover { transform: scale(1.2); }
.color-option.active { border-color: var(--text); }

/* ─── Add column ─── */
.add-column {
  flex: 0 0 140px;
  background: transparent; border: 2px dashed #cbd5e1;
  border-radius: var(--radius);
  display: flex; align-items: center; justify-content: center;
  cursor: pointer; transition: all .15s;
  padding: 24px; color: #9ca3af; font-size: 14px; font-weight: 500;
  min-height: 120px;
}
.add-column:hover { border-color: var(--accent); color: var(--accent); background: #4f46e508; }

/* ─── Modal ─── */
.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,.4); display: flex; align-items: center; justify-content: center; z-index: 200; animation: fadeIn .15s; }
@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
.modal { background: #fff; border-radius: var(--radius); padding: 24px; min-width: 360px; max-width: 90vw; box-shadow: 0 20px 60px rgba(0,0,0,.2); animation: slideUp .2s ease; }
@keyframes slideUp { from { transform: translateY(20px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
.modal h2 { font-size: 18px; margin-bottom: 16px; }
.modal-field { margin-bottom: 14px; }
.modal-field label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 4px; color: var(--text-secondary); }
.modal-field input, .modal-field select, .modal-field textarea { width: 100%; padding: 8px 12px; border: 1px solid var(--border); border-radius: var(--radius-sm); font-size: 14px; outline: none; font-family: inherit; }
.modal-field input:focus, .modal-field select:focus { border-color: var(--accent); box-shadow: 0 0 0 3px #4f46e520; }
.modal-actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 20px; }

/* ─── Search ─── */
.search-input { padding: 7px 12px; border: 1px solid var(--border); border-radius: var(--radius-sm); font-size: 14px; outline: none; width: 200px; }
.search-input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px #4f46e520; }
.highlight { background: #fef08a; border-radius: 3px; }

/* ─── Save indicator ─── */
.save-status { font-size: 12px; color: var(--text-secondary); margin-left: 8px; transition: color .3s; }
.save-status.saved { color: #10b981; }
.save-status.saving { color: #f59e0b; }

/* ─── Toast ─── */
.toast { position: fixed; bottom: 24px; right: 24px; background: #1a1a2e; color: #fff; padding: 12px 20px; border-radius: var(--radius-sm); font-size: 14px; z-index: 300; animation: slideUp .2s ease; pointer-events: none; }

/* ─── Responsive ─── */
@media (max-width: 768px) {
  .header { padding: 12px 16px; }
  .header h1 { font-size: 18px; }
  .board { padding: 12px 16px; }
  .column { min-width: 260px; flex: 0 0 260px; }
}
</style>
</head>
<body>

<div class="header">
  <h1>🍌 <span>Kanbanana</span></h1>
  <div class="header-actions">
    <span class="save-status" id="saveStatus"></span>
    <input class="search-input" type="text" placeholder="🔍 Search cards..." id="searchInput">
    <button class="btn btn-outline" onclick="showHistoryModal()">🕓 History</button>
    <button class="btn btn-outline" onclick="downloadBackup()">⬇ Backup</button>
    <button class="btn btn-outline" onclick="document.getElementById('importFile').click()">⬆ Import</button>
    <input type="file" id="importFile" accept=".json" style="display:none" onchange="importBackup(event)">
    <button class="btn btn-primary" onclick="showAddCardModal()">+ Add Card</button>
  </div>
</div>

<div class="board" id="board"></div>
<div id="modalContainer"></div>

<script>
// ────────────────────────────── State & Persistence ──────────────────────────────
const API = '/api/data';
const defaultData = ${JSON.stringify(DEFAULT_DATA)};

let data = null;
let version = 0;
let nextCardId = 1;

async function loadData() {
  try {
    const resp = await fetch(API);
    if (!resp.ok) throw new Error('Failed to load');
    const result = await resp.json();
    data = result.data;
    version = result.version;
  } catch (e) {
    data = JSON.parse(JSON.stringify(defaultData));
    version = 0;
  }
  initNextId();
}

function initNextId() {
  data.columns.forEach(c => c.cards.forEach(card => {
    const num = parseInt(card.id?.split('-')[1]);
    if (num >= nextCardId) nextCardId = num + 1;
  }));
}

async function saveData() {
  document.getElementById('saveStatus').textContent = 'Saving...';
  document.getElementById('saveStatus').className = 'save-status saving';
  try {
    const resp = await fetch(API, { method: 'PUT', body: JSON.stringify({ data, version }), headers: { 'Content-Type': 'application/json' } });
    if (resp.status === 409) {
      document.getElementById('saveStatus').textContent = '⚠ Conflict — reloading...';
      document.getElementById('saveStatus').className = 'save-status saving';
      toast('Someone else made changes. Reloading...');
      setTimeout(async () => { await loadData(); render(); }, 800);
      return;
    }
    if (!resp.ok) throw new Error('Save failed');
    const result = await resp.json();
    version = result.version;
    document.getElementById('saveStatus').textContent = 'Saved ✓';
    document.getElementById('saveStatus').className = 'save-status saved';
    setTimeout(() => { document.getElementById('saveStatus').textContent = ''; }, 2000);
  } catch (e) {
    document.getElementById('saveStatus').textContent = 'Save failed';
    document.getElementById('saveStatus').className = 'save-status saving';
  }
}

// ────────────────────────────── Drag & Drop ──────────────────────────────
let draggedCard = null;
let dragSourceColId = null;

function handleDragStart(e, cardId, colId) {
  draggedCard = cardId;
  dragSourceColId = colId;
  e.dataTransfer.effectAllowed = 'move';
  e.dataTransfer.setData('text/plain', cardId + '|' + colId);
  setTimeout(() => {
    const card = document.querySelector(\`.card[data-card-id="\${cardId}"]\`);
    if (card) card.classList.add('dragging');
  }, 0);
}

function handleDragEnd(e) {
  const card = document.querySelector(\`.card[data-card-id="\${draggedCard}"]\`);
  if (card) card.classList.remove('dragging');
  document.querySelectorAll('.drag-over, .drag-target').forEach(el => el.classList.remove('drag-over', 'drag-target'));
  draggedCard = null;
  dragSourceColId = null;
}

function handleDragOver(e, colId) {
  e.preventDefault();
  e.dataTransfer.dropEffect = 'move';
  const col = document.getElementById(colId);
  if (col) col.classList.add('drag-over');
}

function handleDragLeave(e, colId) {
  const col = document.getElementById(colId);
  if (col && !col.contains(e.relatedTarget)) col.classList.remove('drag-over');
}

function handleDrop(e, targetColId) {
  e.preventDefault();
  const col = document.getElementById(targetColId);
  if (col) col.classList.remove('drag-over');
  const raw = e.dataTransfer.getData('text/plain');
  if (!raw) return;
  const [cardId, sourceColId] = raw.split('|');
  if (sourceColId === targetColId) return;
  const sourceCol = data.columns.find(c => c.id === sourceColId);
  const targetCol = data.columns.find(c => c.id === targetColId);
  if (!sourceCol || !targetCol) return;
  const cardIndex = sourceCol.cards.findIndex(c => c.id === cardId);
  if (cardIndex === -1) return;
  const cardList = col.querySelector('.card-list');
  let insertIndex = targetCol.cards.length;
  if (cardList) {
    const cards = cardList.querySelectorAll('.card:not(.dragging)');
    const targetCard = [...cards].find(card => e.clientY < card.getBoundingClientRect().top + card.getBoundingClientRect().height / 2);
    if (targetCard) {
      const targetId = targetCard.dataset.cardId;
      insertIndex = targetCol.cards.findIndex(c => c.id === targetId);
      if (insertIndex === -1) insertIndex = targetCol.cards.length;
    }
  }
  const [card] = sourceCol.cards.splice(cardIndex, 1);
  targetCol.cards.splice(insertIndex, 0, card);
  touchCard(card);
  saveData().then(render);
}

// ────────────────────────────── Rendering ──────────────────────────────
function render() {
  const board = document.getElementById('board');
  board.innerHTML = '';
  const searchTerm = document.getElementById('searchInput')?.value?.toLowerCase() || '';

  data.columns.forEach(col => {
    const colEl = document.createElement('div');
    colEl.className = 'column';
    colEl.id = col.id;
    colEl.addEventListener('dragover', e => handleDragOver(e, col.id));
    colEl.addEventListener('dragleave', e => handleDragLeave(e, col.id));
    colEl.addEventListener('drop', e => handleDrop(e, col.id));

    const header = document.createElement('div');
    header.className = 'column-header';
    header.innerHTML = \`
      <div class="column-title-wrap">
        <div class="column-title" contenteditable="true"
             data-col-id="\${col.id}"
             onblur="updateColumnTitle(event, '\${col.id}')"
             onkeydown="if(event.key==='Enter'){event.preventDefault();this.blur()}">\${escapeHtml(col.title)}</div>
      </div>
      <div style="display:flex;align-items:center;justify-content:space-between">
        <div style="display:flex;align-items:center;gap:6px">
          <span class="column-count">\${col.cards.length}</span>
          <button class="btn btn-ghost" title="Column color" style="font-size:15px;padding:4px 6px" onclick="showColorPicker(event, '\${col.id}')">🎨</button>
          <button class="btn btn-ghost" title="Add card" style="font-size:15px;padding:4px 6px" onclick="showAddCardModal('\${col.id}')">+</button>
          <button class="btn btn-ghost" title="Delete column" style="font-size:15px;padding:4px 6px;color:var(--danger)" onclick="deleteColumn('\${col.id}')">✕</button>
        </div>
      </div>
    \`;
    colEl.appendChild(header);
    colEl.style.background = col.color;

    const list = document.createElement('div');
    list.className = 'card-list';

    col.cards.forEach(card => {
      if (searchTerm && !matchesSearch(card, searchTerm)) return;
      const cardEl = document.createElement('div');
      cardEl.className = 'card';
      cardEl.draggable = true;
      cardEl.dataset.cardId = card.id;
      cardEl.addEventListener('dragstart', e => handleDragStart(e, card.id, col.id));
      cardEl.addEventListener('dragend', handleDragEnd);

      let dateHtml = '';
      if (card.date) dateHtml = \`<span class="card-date">📅 \${card.date}</span>\`;
      const updatedHtml = \`<span class="card-date">🕐 Last updated: \${formatTimeAgo(card.updatedAt)}</span>\`;

      cardEl.innerHTML = \`
        <div class="card-header">
          <div class="card-content" contenteditable="true"
               data-card-id="\${card.id}" data-col-id="\${col.id}"
               onblur="updateCardContent(event, '\${col.id}', '\${card.id}')"
               onkeydown="if(event.key==='Escape'){event.preventDefault();this.blur()}"
          >\${highlightText(escapeHtml(card.content), searchTerm)}</div>
        </div>
        <div class="card-meta">\${dateHtml}\${updatedHtml}</div>
        <div class="card-actions">
          <button class="btn btn-ghost btn-sm" title="Date" onclick="event.stopPropagation();setCardDate('\${col.id}','\${card.id}')">📅</button>
          <button class="btn btn-ghost btn-sm" title="Delete" style="color:var(--danger)" onclick="event.stopPropagation();deleteCard('\${col.id}','\${card.id}')">🗑️</button>
        </div>
      \`;
      list.appendChild(cardEl);
    });

    colEl.appendChild(list);
    board.appendChild(colEl);
  });

  const addCol = document.createElement('div');
  addCol.className = 'add-column';
  addCol.innerHTML = '+ Add Column';
  addCol.onclick = () => showAddColumnModal();
  board.appendChild(addCol);
}

function matchesSearch(card, term) {
  return card.content.toLowerCase().includes(term) || (card.date && card.date.toLowerCase().includes(term));
}

function highlightText(text, term) {
  if (!term) return text;
  const regex = new RegExp(\`(\${term.replace(/[.*+?^\${}()|[\\]\\\\\\\\]/g, '\\\\\\\\$&')})\`, 'gi');
  return text.replace(regex, '<mark class="highlight">$1</mark>');
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ────────────────────────────── Card Operations ──────────────────────────────
function touchCard(card) { card.updatedAt = Date.now(); }

async function updateCardContent(e, colId, cardId) {
  const col = data.columns.find(c => c.id === colId);
  if (!col) return;
  const card = col.cards.find(c => c.id === cardId);
  if (!card) return;
  card.content = e.target.innerText.trim() || 'Untitled';
  touchCard(card);
  await saveData();
  render();
}

async function deleteCard(colId, cardId) {
  const col = data.columns.find(c => c.id === colId);
  if (!col) return;
  const idx = col.cards.findIndex(c => c.id === cardId);
  if (idx === -1) return;
  col.cards.splice(idx, 1);
  await saveData();
  render();
  toast('Card deleted');
}

async function setCardDate(colId, cardId) {
  const col = data.columns.find(c => c.id === colId);
  if (!col) return;
  const card = col.cards.find(c => c.id === cardId);
  if (!card) return;
  const today = new Date().toISOString().split('T')[0];
  const date = prompt('Enter date (YYYY-MM-DD):', card.date || today);
  if (date === null) return;
  card.date = date.trim() || '';
  touchCard(card);
  await saveData();
  render();
}

// ────────────────────────────── Column Operations ──────────────────────────────
async function updateColumnTitle(e, colId) {
  const col = data.columns.find(c => c.id === colId);
  if (!col) return;
  col.title = e.target.innerText.trim() || 'Untitled';
  await saveData();
  render();
}

async function deleteColumn(colId) {
  if (data.columns.length <= 1) { toast('Cannot delete the last column'); return; }
  const col = data.columns.find(c => c.id === colId);
  if (!col) return;
  if (!confirm(\`Delete column "\${col.title}" and all its cards?\`)) return;
  data.columns = data.columns.filter(c => c.id !== colId);
  await saveData();
  render();
  toast('Column deleted');
}

function showColorPicker(e, colId) {
  e.stopPropagation();
  const col = data.columns.find(c => c.id === colId);
  if (!col) return;
  const colors = ['#e2e8f0','#fecaca','#fde68a','#a7f3d0','#bfdbfe','#ddd6fe','#fbcfe8','#99f6e4','#fed7aa'];
  const palette = colors.map(c =>
    \`<div class="color-option\${col.color===c?' active':''}" style="background:\${c}" onclick="setColumnColor('\${colId}','\${c}')"></div>\`
  ).join('');
  showModal(\`<h2>Column Color</h2><div class="color-picker">\${palette}</div><div class="modal-actions"><button class="btn btn-outline" onclick="closeModal()">Close</button></div>\`);
}

async function setColumnColor(colId, color) {
  const col = data.columns.find(c => c.id === colId);
  if (!col) return;
  col.color = color;
  await saveData();
  render();
  closeModal();
}

// ────────────────────────────── Modals ──────────────────────────────
function showModal(html) {
  document.getElementById('modalContainer').innerHTML = \`<div class="modal-overlay" onclick="if(event.target===this)closeModal()"><div class="modal">\${html}</div></div>\`;
}
function closeModal() { document.getElementById('modalContainer').innerHTML = ''; }

function showAddCardModal(preSelectedColId) {
  const colOptions = data.columns.map(c => \`<option value="\${c.id}" \${c.id===preSelectedColId?'selected':''}>\${escapeHtml(c.title)}</option>\`).join('');
  showModal(\`
    <h2>Add Card</h2>
    <div class="modal-field"><label>Content</label><textarea id="newCardContent" rows="3" placeholder="What needs to be done?" autofocus></textarea></div>
    <div class="modal-field"><label>Column</label><select id="newCardColumn">\${colOptions}</select></div>
    <div class="modal-field"><label>Due Date</label><input type="date" id="newCardDate"></div>
    <div class="modal-actions">
      <button class="btn btn-outline" onclick="closeModal()">Cancel</button>
      <button class="btn btn-primary" onclick="addCard()">Add Card</button>
    </div>
  \`);
}

async function addCard() {
  const content = document.getElementById('newCardContent').value.trim();
  if (!content) { toast('Please enter card content'); return; }
  const colId = document.getElementById('newCardColumn').value;
  const date = document.getElementById('newCardDate').value;
  const col = data.columns.find(c => c.id === colId);
  if (!col) return;
  col.cards.push({ id: \`c-\${nextCardId++}\`, content, date, updatedAt: Date.now() });
  await saveData();
  render();
  closeModal();
  toast('Card added');
}

function showAddColumnModal() {
  showModal(\`
    <h2>Add Column</h2>
    <div class="modal-field"><label>Column Name</label><input type="text" id="newColTitle" placeholder="e.g. Review" autofocus></div>
    <div class="modal-field"><label>Color</label>
      <div class="color-picker" id="newColColorPicker">
        \${['#e2e8f0','#fecaca','#fde68a','#a7f3d0','#bfdbfe','#ddd6fe','#fbcfe8','#99f6e4','#fed7aa'].map((c,i) => \`<div class="color-option\${i===6?' active':''}" style="background:\${c}" data-color="\${c}" onclick="selectNewColColor(this)"></div>\`).join('')}
      </div>
      <input type="hidden" id="newColColor" value="#fbcfe8">
    </div>
    <div class="modal-actions">
      <button class="btn btn-outline" onclick="closeModal()">Cancel</button>
      <button class="btn btn-primary" onclick="addColumn()">Add Column</button>
    </div>
  \`);
}

function selectNewColColor(el) {
  document.querySelectorAll('#newColColorPicker .color-option').forEach(o => o.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('newColColor').value = el.dataset.color;
}

async function addColumn() {
  const title = document.getElementById('newColTitle').value.trim();
  if (!title) { toast('Please enter a column name'); return; }
  const color = document.getElementById('newColColor').value;
  data.columns.push({ id: \`col-\${Date.now()}\`, title, color, cards: [] });
  await saveData();
  render();
  closeModal();
  toast('Column added');
}

// ────────────────────────────── Search ──────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  await loadData();
  render();
  document.getElementById('searchInput').addEventListener('input', render);
  startPolling();
});

// ────────────────────────────── Polling ──────────────────────────────
let pollTimer = null;

function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(pollForChanges, 5000);
}

async function pollForChanges() {
  // Don't poll while user is editing
  if (document.activeElement && document.activeElement.isContentEditable) return;
  if (document.activeElement && document.activeElement.tagName === 'INPUT') return;
  if (document.activeElement && document.activeElement.tagName === 'TEXTAREA') return;
  try {
    const resp = await fetch(API);
    if (!resp.ok) return;
    const result = await resp.json();
    if (result.version !== version) {
      data = result.data;
      version = result.version;
      initNextId();
      render();
      toast('🔄 Board updated by someone else');
    }
  } catch (e) { /* network error, ignore */ }
}

// ────────────────────────────── Toast ──────────────────────────────
function toast(msg) {
  const existing = document.querySelector('.toast');
  if (existing) existing.remove();
  const t = document.createElement('div');
  t.className = 'toast';
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 2000);
}

// ────────────────────────────── Helpers ──────────────────────────────
function formatTimeAgo(ts) {
  if (!ts) return 'just now';
  const seconds = Math.floor((Date.now() - ts) / 1000);
  if (seconds < 60) return 'just now';
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return \`\${minutes}m ago\`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return \`\${hours}h ago\`;
  const days = Math.floor(hours / 24);
  if (days < 7) return \`\${days}d ago\`;
  return new Date(ts).toLocaleDateString();
}

// ────────────────────────────── Backup / Import / History ──────────────────────────────
function downloadBackup() {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'kanbanana-backup-' + new Date().toISOString().slice(0, 10) + '.json';
  a.click();
  toast('📥 Backup downloaded');
}

async function importBackup(event) {
  const file = event.target.files[0];
  if (!file) return;
  try {
    const text = await file.text();
    const imported = JSON.parse(text);
    if (!imported.columns) throw new Error('Invalid format');
    // Save with current version (will conflict if stale)
    const resp = await fetch(API, { method: 'PUT', body: JSON.stringify({ data: imported, version }), headers: { 'Content-Type': 'application/json' } });
    if (resp.status === 409) {
      toast('⚠ Conflict — reloading before import');
      await loadData();
      // Retry once
      const resp2 = await fetch(API, { method: 'PUT', body: JSON.stringify({ data: imported, version }), headers: { 'Content-Type': 'application/json' } });
      if (!resp2.ok) throw new Error('Import failed');
    } else if (!resp.ok) {
      throw new Error('Import failed');
    }
    const result = await resp.status === 409 ? (await fetch(API, { method: 'PUT', body: JSON.stringify({ data: imported, version }), headers: { 'Content-Type': 'application/json' } })).json() : resp.json();
    version = result.version;
    data = imported;
    render();
    toast('✅ Backup imported');
  } catch (e) {
    toast('❌ Invalid backup file');
  }
  event.target.value = '';
}

async function showHistoryModal() {
  try {
    const resp = await fetch('/api/history');
    const history = await resp.json();
    const rows = history.length === 0
      ? '<p style="color:#9ca3af;text-align:center;padding:20px">No history yet</p>'
      : history.map(h => \`
        <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 12px;border-bottom:1px solid #e5e7eb">
          <div>
            <strong>v\${h.version}</strong>
            \${h.restoredFrom ? '<span style="font-size:11px;color:#f59e0b;margin-left:6px">(restored from v' + h.restoredFrom + ')</span>' : ''}
            <div style="font-size:12px;color:#6b7280">
              \${new Date(h.timestamp).toLocaleString()} &middot;
              \${h.columnCount} columns &middot;
              \${h.cardCount} cards
            </div>
          </div>
          <button class="btn btn-outline btn-sm" onclick="restoreVersion(\${h.version})">Restore</button>
        </div>
      \`).join('');
    showModal(\`
      <h2>Version History</h2>
      <div style="max-height:400px;overflow-y:auto;margin:-4px -12px">\${rows}</div>
      <div class="modal-actions">
        <button class="btn btn-outline" onclick="closeModal()">Close</button>
      </div>
    \`);
  } catch (e) {
    toast('Failed to load history');
  }
}

async function restoreVersion(v) {
  if (!confirm(\`Restore version \${v}? Current changes will be saved as a new version.\`)) return;
  const resp = await fetch('/api/restore', {
    method: 'POST',
    body: JSON.stringify({ version: v }),
    headers: { 'Content-Type': 'application/json' }
  });
  if (!resp.ok) { toast('Failed to restore'); return; }
  const result = await resp.json();
  await loadData();
  render();
  closeModal();
  toast('✅ Restored version ' + v);
}

function showChangePasswordModal() {
  showModal(\`
    <h2>Change Password</h2>
    <div class="modal-field"><label>Current Password</label><input type="password" id="curPw" placeholder="Current password"></div>
    <div class="modal-field"><label>New Password</label><input type="password" id="newPw" placeholder="New password"></div>
    <div class="modal-actions">
      <button class="btn btn-outline" onclick="closeModal()">Cancel</button>
      <button class="btn btn-primary" onclick="changePassword()">Update</button>
    </div>
  \`);
}

async function changePassword() {
  const cur = document.getElementById('curPw').value;
  const nw = document.getElementById('newPw').value;
  if (!cur || !nw) { toast('Please fill both fields'); return; }
  const resp = await fetch('/api/change-password', {
    method: 'POST',
    body: JSON.stringify({ currentPassword: cur, newPassword: nw }),
    headers: { 'Content-Type': 'application/json' }
  });
  const result = await resp.json();
  if (!resp.ok) { toast('❌ ' + (result.error || 'Failed')); return; }
  closeModal();
  toast('✅ Password updated');
}

// ────────────────────────────── Keyboard shortcuts ──────────────────────────────
document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') { e.preventDefault(); document.getElementById('searchInput').focus(); }
  if ((e.ctrlKey || e.metaKey) && e.key === 'n') { e.preventDefault(); showAddCardModal(); }
});
</script>
</body>
</html>`;

// ─── Export handler ──────────────────────────────────────────────────

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // ── Login endpoint ──
    if (path === '/login' && request.method === 'POST') {
      const formData = await request.formData();
      const pw = formData.get('password') || '';
      const hashed = await hashPassword(pw);
      // Check KV-stored password first, fall back to secret
      const storedHash = await env.KANBAN.get(PASSWORD_KEY);
      const validHash = storedHash || env.PASSWORD_HASH;
      if (hashed !== validHash) {
        return new Response(LOGIN_HTML.replace('{{ERROR}}', 'Incorrect password. Please try again.').replace("style.display = 'block'", "style.display = 'block'; document.getElementById('error').style.display = 'block'"), {
          status: 401,
          headers: { 'Content-Type': 'text/html' }
        });
      }
      const cookieValue = await signCookie('authed', env.COOKIE_SECRET);
      const headers = new Headers();
      headers.set('Location', '/');
      headers.set('Set-Cookie', `auth=${cookieValue}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000`);
      return new Response(null, { status: 302, headers });
    }

    // ── Auth check for protected routes ──
    const authed = await isAuthed(request, env);

    // ── API: Change password ──
    if (path === '/api/change-password' && request.method === 'POST') {
      if (!authed) return new Response('Unauthorized', { status: 401 });
      const body = await request.json().catch(() => null);
      if (!body || !body.currentPassword || !body.newPassword) {
        return new Response(JSON.stringify({ error: 'Missing passwords' }), { status: 400 });
      }
      // Verify current password
      const currentHash = await hashPassword(body.currentPassword);
      const storedHash = await env.KANBAN.get(PASSWORD_KEY);
      const validHash = storedHash || env.PASSWORD_HASH;
      if (currentHash !== validHash) {
        return new Response(JSON.stringify({ error: 'Current password is incorrect' }), { status: 403 });
      }
      // Store new password hash in KV
      const newHash = await hashPassword(body.newPassword);
      await env.KANBAN.put(PASSWORD_KEY, newHash);
      return new Response(JSON.stringify({ ok: true }));
    }

    // ── API: Get data ──
    if (path === '/api/data' && request.method === 'GET') {
      if (!authed) return new Response('Unauthorized', { status: 401 });
      const currentVersion = parseInt(await env.KANBAN.get(VERSION_KEY) || '0');
      const raw = await env.KANBAN.get(KV_KEY + '-v' + currentVersion);
      const data = raw ? JSON.parse(raw) : JSON.parse(JSON.stringify(DEFAULT_DATA));
      return new Response(JSON.stringify({ data, version: currentVersion }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // ── API: Save data ──
    if (path === '/api/data' && request.method === 'PUT') {
      if (!authed) return new Response('Unauthorized', { status: 401 });
      const body = await request.json().catch(() => null);
      if (!body || typeof body.version !== 'number') {
        return new Response(JSON.stringify({ error: 'Missing version' }), { status: 400 });
      }
      const currentVersion = parseInt(await env.KANBAN.get(VERSION_KEY) || '0');
      if (body.version !== currentVersion) {
        return new Response(JSON.stringify({ error: 'Conflict', currentVersion }), {
          status: 409,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      const newVersion = currentVersion + 1;
      // Save versioned data
      await env.KANBAN.put(KV_KEY + '-v' + newVersion, JSON.stringify(body.data));
      await env.KANBAN.put(VERSION_KEY, String(newVersion));
      // Update history
      const historyRaw = await env.KANBAN.get(HISTORY_KEY);
      let history = historyRaw ? JSON.parse(historyRaw) : [];
      const cardCount = body.data.columns.reduce((s, c) => s + c.cards.length, 0);
      history.unshift({ version: newVersion, timestamp: Date.now(), columnCount: body.data.columns.length, cardCount });
      if (history.length > MAX_VERSIONS) history = history.slice(0, MAX_VERSIONS);
      // Clean up old version beyond window
      const oldestToDelete = newVersion - MAX_VERSIONS;
      if (oldestToDelete > 0) {
        ctx.waitUntil((async () => {
          await env.KANBAN.delete(KV_KEY + '-v' + oldestToDelete);
        })());
      }
      await env.KANBAN.put(HISTORY_KEY, JSON.stringify(history));
      return new Response(JSON.stringify({ ok: true, version: newVersion }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // ── API: Get history ──
    if (path === '/api/history' && request.method === 'GET') {
      if (!authed) return new Response('Unauthorized', { status: 401 });
      const raw = await env.KANBAN.get(HISTORY_KEY);
      const history = raw ? JSON.parse(raw) : [];
      return new Response(JSON.stringify(history), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // ── API: Restore version ──
    if (path === '/api/restore' && request.method === 'POST') {
      if (!authed) return new Response('Unauthorized', { status: 401 });
      const body = await request.json().catch(() => null);
      if (!body || typeof body.version !== 'number') {
        return new Response(JSON.stringify({ error: 'Missing version' }), { status: 400 });
      }
      const raw = await env.KANBAN.get(KV_KEY + '-v' + body.version);
      if (!raw) return new Response(JSON.stringify({ error: 'Version not found' }), { status: 404 });
      const data = JSON.parse(raw);
      const currentVersion = parseInt(await env.KANBAN.get(VERSION_KEY) || '0');
      const newVersion = currentVersion + 1;
      await env.KANBAN.put(KV_KEY + '-v' + newVersion, JSON.stringify(data));
      await env.KANBAN.put(VERSION_KEY, String(newVersion));
      // Update history
      const historyRaw = await env.KANBAN.get(HISTORY_KEY);
      let history = historyRaw ? JSON.parse(historyRaw) : [];
      const cardCount = data.columns.reduce((s, c) => s + c.cards.length, 0);
      history.unshift({ version: newVersion, timestamp: Date.now(), columnCount: data.columns.length, cardCount, restoredFrom: body.version });
      if (history.length > MAX_VERSIONS) history = history.slice(0, MAX_VERSIONS);
      await env.KANBAN.put(HISTORY_KEY, JSON.stringify(history));
      return new Response(JSON.stringify({ ok: true, version: newVersion }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // ── Serve app or login page ──
    if (!authed) {
      return new Response(LOGIN_HTML.replace('{{ERROR}}', ''), {
        headers: { 'Content-Type': 'text/html' }
      });
    }

    return new Response(KANBAN_HTML, {
      headers: { 'Content-Type': 'text/html' }
    });
  }
};
