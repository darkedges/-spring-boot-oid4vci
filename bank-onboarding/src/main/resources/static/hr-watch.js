/** Update the HR list without reloading the create form or losing decision notes. */
export function notice(previous, current, name) {
  if (!previous || previous === current) return '';
  if (current === 'APPROVED') return `${name}: identity approved. The staff credential can now be collected.`;
  if (current === 'ACTIVE') return `${name}: approved and active. The staff credential has been collected.`;
  if (current === 'REVIEW') return `${name}: identity verification received and ready for HR review.`;
  return `${name}: status changed to ${current.toLowerCase()}.`;
}

export function updateCards(document, incoming, announce) {
  const list = document.querySelector('#hire-list');
  const incomingIds = new Set([...incoming.querySelectorAll('#hire-list > article')].map(card => card.id));
  for (const card of list.querySelectorAll(':scope > article')) if (!incomingIds.has(card.id)) card.remove();
  const oldHistory = document.querySelector('#hire-history');
  const newHistory = incoming.querySelector('#hire-history');
  if (newHistory) {
    const history = document.importNode(newHistory, true);
    if (oldHistory?.open) history.open = true;
    if (oldHistory) oldHistory.replaceWith(history); else list.after(history);
  } else oldHistory?.remove();
  for (const fresh of incoming.querySelectorAll('#hire-list > article')) {
    const old = document.getElementById(fresh.id);
    if (!old) { list.prepend(document.importNode(fresh, true)); continue; }
    const message = notice(old.dataset.status, fresh.dataset.status, fresh.querySelector('h2').textContent);
    if (message) announce(message);
    if (old.isEqualNode(fresh)) continue;
    const replacement = document.importNode(fresh, true);
    // Poll responses can carry new CSRF masks even when the hire has not changed.
    // Preserve in-progress decisions, including the fresh Passport requirement.
    const editable = 'textarea,input[type="checkbox"]';
    for (const field of old.querySelectorAll(editable)) {
      const form = [...replacement.querySelectorAll('form')].find(f => f.getAttribute('action') === field.form?.getAttribute('action'));
      const target = form && [...form.querySelectorAll(editable)].find(f => f.name === field.name && f.type === field.type);
      if (target) {
        if (field.type === 'checkbox') target.checked = field.checked;
        else target.value = field.value;
      }
    }
    const focused = document.activeElement;
    const nextFocus = focused?.matches?.(editable)
      ? [...replacement.querySelectorAll(editable)].find(f => f.name === focused.name && f.type === focused.type && f.form?.getAttribute('action') === focused.form?.getAttribute('action')) : null;
    const selection = nextFocus?.tagName === 'TEXTAREA' ? [focused.selectionStart, focused.selectionEnd] : null;
    old.replaceWith(replacement);
    if (nextFocus) { nextFocus.focus({ preventScroll: true }); if (selection) nextFocus.setSelectionRange(...selection); }
  }
}

export function watch(document, window) {
  const status = document.querySelector('#watch-status');
  const notifications = document.querySelector('#watch-notifications');
  const originalTitle = document.title;
  let timer, stopped = false, polling = false;
  const announce = message => {
    const item = document.createElement('li'); item.textContent = message;
    notifications.prepend(item);
    while (notifications.children.length > 10) notifications.lastElementChild.remove();
    document.title = `HR update - ${originalTitle}`;
  };
  async function poll() {
    if (stopped || polling) return;
    window.clearTimeout(timer);
    if (document.hidden) { timer = window.setTimeout(poll, 5000); return; }
    polling = true;
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 15000);
    try {
      const response = await window.fetch('/hr', { credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: controller.signal });
      if (response.status === 401 || response.status === 403) {
        stopped = true; status.textContent = 'Live updates stopped. Reload this page to sign in again.'; return;
      }
      if (!response.ok) throw new Error('poll failed');
      const html = await response.text();
      if (stopped) return;
      const incoming = new window.DOMParser().parseFromString(html, 'text/html');
      if (!incoming.querySelector('#hire-list')) throw new Error('unexpected page');
      updateCards(document, incoming, announce);
      status.textContent = 'Live updates on. Checking every 5 seconds.';
    } catch {
      status.textContent = 'Live updates unavailable. Retrying automatically; reload if your session expired.';
    } finally {
      window.clearTimeout(timeout); polling = false;
      if (!stopped) timer = window.setTimeout(poll, 5000);
    }
  }
  document.addEventListener('click', event => {
    const link = event.target.closest?.('a[href^="#hire-"]');
    if (link) {
      const card = document.getElementById(link.getAttribute('href').slice(1));
      const history = card?.closest('details');
      if (history) history.open = true;
    }
  });
  document.addEventListener('visibilitychange', () => { if (!document.hidden) void poll(); });
  document.addEventListener('submit', () => { stopped = true; window.clearTimeout(timer); });
  window.addEventListener('pagehide', () => { stopped = true; window.clearTimeout(timer); });
  window.addEventListener('pageshow', event => { if (event.persisted) { stopped = false; void poll(); } });
  timer = window.setTimeout(poll, 5000);
}

if (typeof document !== 'undefined' && document.querySelector('#hire-list')) watch(document, window);
