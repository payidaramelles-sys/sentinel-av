/* Sentinel arayüzü — WebView2 köprüsü ve görünüm mantığı */

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

/* ---------- köprü ---------- */

const bridge = (() => {
  const pending = new Map();
  let seq = 0;
  const webview = window.chrome && window.chrome.webview;

  if (webview) {
    webview.addEventListener('message', (event) => {
      const message = event.data;
      if (!message) return;

      if (message.event) {
        onEvent(message.event, message.data);
        return;
      }

      const resolver = pending.get(message.id);
      if (!resolver) return;
      pending.delete(message.id);
      if (message.ok) resolver.resolve(message.data);
      else resolver.reject(new Error(message.error || 'Bilinmeyen hata'));
    });
  }

  return {
    call(command, args = {}) {
      if (!webview) return Promise.reject(new Error('WebView2 köprüsü yok'));
      const id = ++seq;
      return new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject });
        webview.postMessage({ id, cmd: command, args });
      });
    }
  };
})();

/* ---------- yardımcılar ---------- */

const state = {
  status: null,
  events: [],
  quarantine: [],
  trust: null,
  filter: 'all',
  page: 'overview',
  scanning: false
};

const PAGE_META = {
  overview: ['Genel Bakış', 'Koruma durumu ve son etkinlik'],
  scan: ['Tarama', 'Hızlı veya derin tarama başlat'],
  quarantine: ['Karantina', 'Şifreli karantina ve geri yükleme'],
  trust: ['Güven', 'Engellenen uygulamalar için izin listesi'],
  events: ['Olaylar', 'Hash zincirli günlük kayıtları'],
  settings: ['Ayarlar', 'Yapılandırma ve kısayollar']
};

const esc = (value) => String(value ?? '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;');

const num = (value) => Number(value ?? 0).toLocaleString('tr-TR');
const pad = (value) => String(value).padStart(2, '0');

function size(bytes) {
  const value = Number(bytes ?? 0);
  if (value >= 1048576) return (value / 1048576).toFixed(1) + ' MB';
  if (value >= 1024) return (value / 1024).toFixed(1) + ' KB';
  return value + ' B';
}

function timeOf(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '—';
  return pad(date.getHours()) + ':' + pad(date.getMinutes()) + ':' + pad(date.getSeconds());
}

const SEVERITY = { critical: 'Kritik', error: 'Hata', warning: 'Uyarı', info: 'Bilgi' };

function toast(text, kind = 'success') {
  const host = $('#toasts');
  const element = document.createElement('div');
  element.className = 'toast ' + kind;
  element.textContent = text;
  host.appendChild(element);
  setTimeout(() => {
    element.style.opacity = '0';
    element.style.transition = 'opacity .2s ease';
    setTimeout(() => element.remove(), 220);
  }, 3600);
}

/* ---------- olaylar ---------- */

function onEvent(name, data) {
  if (name === 'scan.started') {
    state.scanning = true;
    setScanBusy(true);
    $('#scanState').textContent = data.deep ? 'Derin tarama sürüyor…' : 'Hızlı tarama sürüyor…';
    $('#scanStats').textContent = '';
    $('#scanFile').textContent = 'Dosyalar taranıyor…';
    $('#scanBar').parentElement.classList.add('running');
    if (state.page !== 'scan') navigate('scan');
  }

  if (name === 'scan.progress') {
    $('#scanState').textContent = 'Taranıyor…';
    $('#scanStats').textContent = num(data.scanned) + ' dosya · ' + num(data.bad) + ' kötü · ' + num(data.suspicious) + ' şüpheli';
    $('#scanFile').textContent = data.file || '—';
  }

  if (name === 'scan.done') {
    state.scanning = false;
    setScanBusy(false);
    $('#scanBar').parentElement.classList.remove('running');
    $('#scanBar').style.width = '100%';
    $('#scanState').textContent = data.bad > 0 ? 'Tarama bitti — kötü dosya var' : 'Tarama bitti';
    $('#scanStats').textContent = num(data.scanned) + ' dosya · ' + num(data.bad) + ' kötü · ' + num(data.suspicious) + ' şüpheli';
    $('#scanFile').textContent = (data.deep ? 'Derin' : 'Hızlı') + ' tarama · ' + data.seconds + ' sn';
    $('#lastScanned').textContent = num(data.scanned);
    $('#lastBad').textContent = num(data.bad);
    $('#lastSus').textContent = data.suspicious + ' şüpheli';
    $('#lastTime').textContent = data.seconds;
    $('#lastKind').textContent = data.deep ? 'derin tarama' : 'hızlı tarama';
    refresh();
  }

  if (name === 'toast') toast(data.text, data.kind);
}

/* ---------- gezinme ---------- */

function navigate(page) {
  if (!PAGE_META[page]) page = 'overview';
  state.page = page;

  $$('.nav-item').forEach((item) => item.classList.toggle('is-active', item.dataset.page === page));
  $$('.page').forEach((section) => section.classList.toggle('is-active', section.dataset.pageEl === page));

  const [title, sub] = PAGE_META[page];
  $('#pageTitle').textContent = title;
  $('#pageSub').textContent = sub;

  if (page === 'events' || page === 'overview') loadEvents();
  if (page === 'quarantine') loadQuarantine();
  if (page === 'trust') loadTrust();
  if (page === 'settings') renderSettings();
}

/* ---------- yükleme ---------- */

async function refresh() {
  try {
    const status = await bridge.call('status');
    state.status = status;
    renderStatus(status);
  } catch (error) {
    $('#miniText').textContent = 'Bağlantı yok';
    $('#miniStatus .dot').className = 'dot dot-off';
  }
}

async function loadEvents() {
  try {
    const events = await bridge.call('events', { limit: 250 });
    state.events = events;
    renderFeed();
    renderEvents();
  } catch { /* yoksay */ }
}

async function loadQuarantine() {
  try {
    state.quarantine = await bridge.call('quarantine.list');
    renderQuarantine();
  } catch { /* yoksay */ }
}

async function loadTrust() {
  try {
    state.trust = await bridge.call('trust.status');
    renderTrust();
  } catch (error) {
    toast(error.message, 'error');
  }
}

/* ---------- görünüm ---------- */

function renderStatus(status) {
  const counters = status.counters;
  $('#statTotal').textContent = num(counters.total);
  $('#statClean').textContent = num(counters.clean) + ' temiz · ' + num(counters.suspicious) + ' şüpheli';
  $('#statBad').textContent = num(counters.malicious);
  $('#statSus').textContent = num(counters.suspicious) + ' şüpheli dosya';
  $('#statQuarantine').textContent = num(status.quarantine);
  $('#statQuiet').textContent = pad(status.quiet.start) + ':00–' + pad(status.quiet.end) + ':00';

  const badge = $('#navQuarantine');
  badge.textContent = num(status.quarantine);
  badge.hidden = status.quarantine === 0;

  $('#miniStatus .dot').className = 'dot ' + (status.engines.defender ? 'dot-ok' : 'dot-warn');
  $('#miniText').textContent = status.engines.defender ? 'Koruma etkin' : 'Defender bulunamadı';

  $('#heroText').textContent = status.engines.defender
    ? 'Defender kalkanı açık, Sentinel indirme ve geçici klasörleri izliyor.'
    : 'Defender motoru bulunamadı; Sentinel yalnızca yerleşik kurallarla çalışıyor.';

  const chips = [
    ['Defender', status.engines.defender],
    ['YARA-X', status.engines.yaraX],
    ['ClamAV', status.engines.clamAv],
    ['Davranış izleyici', status.behavior]
  ].map(([label, on]) =>
    `<span class="chip"><span class="dot ${on ? 'dot-ok' : 'dot-off'}"></span>${esc(label)}</span>`);

  chips.push(`<span class="chip">${esc(status.mode === 'DryRun' ? 'Sadece izleme' : status.mode === 'Auto' ? 'Otomatik karantina' : 'Bildirim modu')}</span>`);

  if (status.sac === 1)
    chips.push('<span class="chip chip-warn">Smart App Control açık</span>');

  $('#heroChips').innerHTML = chips.join('');

  $('#sigVersion').textContent = 'imza ' + esc(status.signatureVersion);

  const engines = [
    ['Yerleşik imzalar', status.engines.builtin],
    ['Windows Defender', status.engines.defender],
    ['YARA-X kuralları', status.engines.yaraX],
    ['ClamAV (derin tarama)', status.engines.clamAv]
  ];
  $('#engines').innerHTML = engines.map(([name, on]) => `
    <li>
      <span class="dot ${on ? 'dot-ok' : 'dot-off'}"></span>
      <span class="name">${esc(name)}</span>
      <span class="state ${on ? 'on' : ''}">${on ? 'etkin' : 'kapalı'}</span>
    </li>`).join('');

  $$('#modeSeg button').forEach((button) => {
    button.classList.toggle('is-active', button.dataset.mode === status.mode);
  });

  renderSettings();
}

function renderFeed() {
  const items = state.events.slice(0, 7);
  if (!items.length) {
    $('#feed').innerHTML = '<li class="empty">Henüz olay yok.</li>';
    return;
  }

  $('#feed').innerHTML = items.map((item) => `
    <li>
      <span class="sev sev-${esc(item.severity)}"></span>
      <span class="when">${timeOf(item.ts)}</span>
      <span class="what" title="${esc(item.message)}">${esc(item.message)}</span>
    </li>`).join('');
}

function renderEvents() {
  const filtered = state.filter === 'all'
    ? state.events
    : state.events.filter((item) => item.severity === state.filter);

  if (!filtered.length) {
    $('#eventsBody').innerHTML = '<tr><td colspan="4" class="empty">Bu filtrede kayıt yok.</td></tr>';
    return;
  }

  $('#eventsBody').innerHTML = filtered.map((item) => {
    const tone = item.severity === 'critical' || item.severity === 'error'
      ? 'malicious'
      : item.severity === 'warning' ? 'suspicious' : 'unknown';
    return `
      <tr>
        <td class="mono">${timeOf(item.ts)}</td>
        <td>${esc(item.type)}</td>
        <td><span class="pill ${tone}">${esc(SEVERITY[item.severity] || item.severity)}</span></td>
        <td class="path" title="${esc(item.message)}">${esc(item.message)}</td>
      </tr>`;
  }).join('');
}

function renderQuarantine() {
  if (!state.quarantine.length) {
    $('#quarantineBody').innerHTML = '<tr><td colspan="5" class="empty">Karantina boş.</td></tr>';
    return;
  }

  $('#quarantineBody').innerHTML = state.quarantine.map((item) => `
    <tr>
      <td class="mono">${timeOf(item.createdAt)}</td>
      <td class="path" title="${esc(item.originalPath)}">${esc(item.originalPath)}</td>
      <td><span class="pill ${esc(item.verdict.toLowerCase())}">${esc(item.verdict)}</span></td>
      <td class="right mono">${size(item.size)}</td>
      <td class="right">
        <div class="row-actions">
          <button class="mini-btn" data-restore="${esc(item.id)}">Geri yükle</button>
          <button class="mini-btn danger" data-delete="${esc(item.id)}">Sil</button>
        </div>
      </td>
    </tr>`).join('');
}

function renderSettings() {
  const status = state.status;
  if (!status) return;

  const rows = [
    ['Veri kökü', status.root],
    ['Yapılandırma', status.configPath],
    ['İmza sürümü', status.signatureVersion],
    ['Yanıt modu', status.mode],
    ['İzlenen yollar', status.watchPaths.join('  ·  ')],
    ['Haftalık tarama', status.schedule.weeklyEnabled
      ? status.schedule.intervalDays + ' günde bir, sakin saatte'
      : 'kapalı'],
    ['Yönetici', status.admin ? 'evet' : 'hayır'],
    ['Davranış izleyici', status.behavior ? 'etkin' : 'kapalı']
  ];

  $('#settingsList').innerHTML = rows.map(([key, value]) =>
    `<dt>${esc(key)}</dt><dd title="${esc(value)}">${esc(value)}</dd>`).join('');
}

const SAC_TEXT = { 0: 'Kapalı', 1: 'Zorunlu', 2: 'Değerlendirme' };
const TRUST_MODE_TEXT = { off: 'kapalı', audit: 'denetim', enforce: 'zorunlu' };
const TRUST_KIND_TEXT = { publisher: 'Yayıncı', hash: 'Özet', path: 'Yol', auto: 'Otomatik' };

function renderTrust() {
  const trust = state.trust;
  if (!trust) return;

  const mode = trust.enforcement || 'off';
  $('#trustSac').textContent = SAC_TEXT[trust.sac] ?? 'Bilinmiyor';
  $('#trustSacHint').textContent = trust.sac === 0
    ? 'Kapatıldı: imzasız ve bilinmeyen uygulamalar da çalışabilir.'
    : trust.sac === -1
      ? 'Durum okunamadı.'
      : 'Yalnızca Microsoft tarafından güvenilen uygulamalar çalışır, tek tek izin verilemez.';
  $('#trustCount').textContent = num(trust.ruleCount);
  $('#trustStatePath').textContent = trust.statePath || '—';
  $('#trustAdmin').textContent = trust.admin ? 'yönetici oturumu' : 'standart kullanıcı';
  $('#trustSummary').textContent = num(trust.ruleCount) + ' kural · mod ' + (TRUST_MODE_TEXT[mode] || mode);

  $$('#trustMode button').forEach((button) => {
    button.classList.toggle('is-active', button.dataset.trustMode === mode);
  });

  const badge = $('#navTrust');
  badge.textContent = num(trust.ruleCount);
  badge.hidden = trust.ruleCount === 0;

  $('#trustAdminBar').hidden = trust.admin || mode === 'off';

  if (!trust.rules || !trust.rules.length) {
    $('#trustBody').innerHTML = '<tr><td colspan="5" class="empty">Henüz kural yok. Aşağıdan bir klasör veya dosya ekleyin.</td></tr>';
    return;
  }

  $('#trustBody').innerHTML = trust.rules.map((rule) => `
    <tr>
      <td><span class="pill unknown">${esc(TRUST_KIND_TEXT[rule.kind] || rule.kind)}</span></td>
      <td class="path" title="${esc(rule.target)}">${esc(rule.display || rule.target)}</td>
      <td>${esc(rule.collection || '—')}</td>
      <td class="path" title="${esc(rule.reason || '')}">${esc(rule.reason || '—')}</td>
      <td class="right">
        <button class="mini-btn danger" data-trust-remove="${esc(rule.id)}">Kaldır</button>
      </td>
    </tr>`).join('');
}

async function addTrust() {
  const path = $('#trustPath').value.trim();
  if (!path) {
    toast('Bir dosya veya klasör yolu girin', 'error');
    return;
  }

  const button = $('#trustAdd');
  button.disabled = true;
  try {
    const result = await bridge.call('trust.add', {
      path,
      kind: $('#trustKind').value,
      reason: $('#trustReason').value.trim()
    });
    const label = result.rule ? (result.rule.display || result.rule.target) : path;
    toast('Güven listesine eklendi: ' + label);
    $('#trustPath').value = '';
    $('#trustReason').value = '';
    await loadTrust();
    if (result.enforcement === 'off')
      toast('Kural kaydedildi; etkili olması için modu Denetim veya Zorunlu yapın', 'warn');
  } catch (error) {
    toast(error.message, 'error');
  } finally {
    button.disabled = false;
  }
}

async function removeTrust(id) {
  if (!confirm('Bu kural kaldırılsın mı?')) return;
  try {
    await bridge.call('trust.remove', { id });
    toast('Kural kaldırıldı');
    await loadTrust();
  } catch (error) {
    toast(error.message, 'error');
  }
}

async function setTrustMode(mode) {
  try {
    const result = await bridge.call('trust.mode', { mode });
    await loadTrust();
    if (result.needsAdmin)
      toast('Mod kaydedildi; uygulamak için yönetici onayı gerekiyor', 'warn');
    else
      toast('AppLocker modu: ' + (TRUST_MODE_TEXT[mode] || mode));
  } catch (error) {
    toast(error.message, 'error');
  }
}

async function applyTrustElevated() {
  const button = $('#trustApplyElevated');
  button.disabled = true;
  button.textContent = 'Onay bekleniyor…';
  try {
    const result = await bridge.call('trust.applyElevated');
    toast(result.applied ? 'Politika uygulandı' : 'Yönetici onayı verilmedi',
      result.applied ? 'success' : 'error');
    await loadTrust();
  } catch (error) {
    toast(error.message, 'error');
  } finally {
    button.disabled = false;
    button.textContent = 'Yönetici olarak uygula';
  }
}

async function pickTrustPath(kind) {
  try {
    const result = await bridge.call('trust.browse', { kind });
    if (result.path) $('#trustPath').value = result.path;
  } catch (error) {
    toast(error.message, 'error');
  }
}

function setScanBusy(busy) {
  $$('[data-scan]').forEach((card) => {
    card.disabled = busy;
    card.style.opacity = busy ? '.6' : '1';
  });
  $('#heroScan').disabled = busy;
}

/* ---------- eylemler ---------- */

async function startScan(deep) {
  if (state.scanning) return;
  try {
    state.scanning = true;
    setScanBusy(true);
    await bridge.call('scan.start', { deep: Boolean(deep) });
  } catch (error) {
    state.scanning = false;
    setScanBusy(false);
    toast(error.message, 'error');
  }
}

async function restoreQuarantine(id) {
  try {
    const result = await bridge.call('quarantine.restore', { id });
    toast('Geri yüklendi: ' + result.destination);
    await loadQuarantine();
    refresh();
  } catch (error) {
    toast(error.message, 'error');
  }
}

async function deleteQuarantine(id) {
  try {
    await bridge.call('quarantine.delete', { id });
    toast('Karantina kaydı silindi');
    await loadQuarantine();
    refresh();
  } catch (error) {
    toast(error.message, 'error');
  }
}

async function openSomething(which) {
  try {
    if (which === 'report') await bridge.call('report.open');
    else if (which === 'config') await bridge.call('config.open');
    else await bridge.call('folder.open', { which });
  } catch (error) {
    toast(error.message, 'error');
  }
}

/* ---------- tema ---------- */

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  localStorage.setItem('sentinel.theme', theme);
}

/* ---------- bağlama ---------- */

function bind() {
  $('#nav').addEventListener('click', (event) => {
    const item = event.target.closest('.nav-item');
    if (item) navigate(item.dataset.page);
  });

  document.addEventListener('click', (event) => {
    const nav = event.target.closest('[data-nav]');
    if (nav) navigate(nav.dataset.nav);

    const opener = event.target.closest('[data-open]');
    if (opener) openSomething(opener.dataset.open);

    const action = event.target.closest('[data-action="report"]');
    if (action) openSomething('report');

    const scan = event.target.closest('[data-scan]');
    if (scan) startScan(scan.dataset.scan === 'deep');

    const restore = event.target.closest('[data-restore]');
    if (restore) restoreQuarantine(restore.dataset.restore);

    const remove = event.target.closest('[data-delete]');
    if (remove) deleteQuarantine(remove.dataset.delete);

    const filter = event.target.closest('[data-filter]');
    if (filter) {
      state.filter = filter.dataset.filter;
      $$('#eventFilters .chip').forEach((chip) =>
        chip.classList.toggle('is-active', chip === filter));
      renderEvents();
    }

    const trustMode = event.target.closest('[data-trust-mode]');
    if (trustMode) setTrustMode(trustMode.dataset.trustMode);

    const trustRemove = event.target.closest('[data-trust-remove]');
    if (trustRemove) removeTrust(trustRemove.dataset.trustRemove);
  });

  $('#heroScan').addEventListener('click', () => startScan(false));
  $('#trustAdd').addEventListener('click', addTrust);
  $('#trustPickFolder').addEventListener('click', () => pickTrustPath('folder'));
  $('#trustPickFile').addEventListener('click', () => pickTrustPath('file'));
  $('#trustApplyElevated').addEventListener('click', applyTrustElevated);
  $('#trustPath').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') addTrust();
  });
  $('#refreshBtn').addEventListener('click', async () => {
    await refresh();
    await loadEvents();
    if (state.page === 'quarantine') await loadQuarantine();
    toast('Yenilendi');
  });

  $('#modeSeg').addEventListener('click', async (event) => {
    const button = event.target.closest('button[data-mode]');
    if (!button) return;
    try {
      await bridge.call('mode.set', { mode: button.dataset.mode });
      await refresh();
      toast('Yanıt modu: ' + (button.dataset.mode === 'DryRun' ? 'sadece izleme'
        : button.dataset.mode === 'Notify' ? 'bildir' : 'otomatik'));
    } catch (error) {
      toast(error.message, 'error');
    }
  });

  $('#themeBtn').addEventListener('click', () => {
    applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
  });
}

/* ---------- başlangıç ---------- */

// Hata ayıklama / duman testi kancası
window.sentinel = { startScan, refresh, loadEvents, loadQuarantine, loadTrust, navigate };

(async function start() {
  const saved = localStorage.getItem('sentinel.theme');
  applyTheme(saved || (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'));

  bind();
  const startPage = (location.hash || '').replace('#', '').trim();
  navigate(PAGE_META[startPage] ? startPage : 'overview');

  await refresh();
  await loadEvents();
  await loadQuarantine();
  await loadTrust();

  setInterval(() => {
    if (document.hidden) return;
    refresh();
  }, 3000);

  setInterval(() => {
    if (document.hidden) return;
    if (state.page === 'events' || state.page === 'overview') loadEvents();
  }, 4000);
})();
