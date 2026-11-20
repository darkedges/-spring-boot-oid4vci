export function watchPresentation(document, window) {
  const view = document.querySelector('#presentation-watch');
  if (!view) return;
  let timer, busy = false, stopped = false;
  async function poll() {
    if (busy || stopped) return;
    window.clearTimeout(timer);
    if (document.hidden) { timer = window.setTimeout(poll, 2000); return; }
    busy = true;
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 10000);
    try {
      const response = await window.fetch(view.dataset.statusUrl, { credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: controller.signal });
      if (response.status === 401 || response.status === 403) {
        stopped = true;
        view.textContent = 'This request is no longer available in this browser session. Start a new request.';
        return;
      }
      if (!response.ok) throw new Error('Status unavailable');
      const result = await response.json();
      if (stopped) return;
      if (result.status === 'complete') {
        stopped = true;
        view.textContent = 'Presentation accepted. Continuing…';
        window.location.replace(view.dataset.resultUrl);
      } else if (result.status === 'expired') {
        stopped = true;
        view.textContent = 'This presentation request expired. Start a new request.';
      } else if (result.status === 'pending') {
        view.textContent = 'Waiting for your wallet. This page will continue automatically after a successful presentation.';
      } else throw new Error('Unexpected status');
    } catch {
      view.textContent = 'Unable to check your presentation. Retrying automatically; you can also use Continue after presentation.';
    } finally {
      busy = false; window.clearTimeout(timeout);
      if (!stopped) timer = window.setTimeout(poll, 2000);
    }
  }
  document.addEventListener('visibilitychange', () => { if (!document.hidden) void poll(); });
  window.addEventListener('pagehide', () => { stopped = true; window.clearTimeout(timer); });
  window.addEventListener('pageshow', event => { if (event.persisted) { stopped = false; void poll(); } });
  void poll();
}
if (typeof document !== 'undefined') watchPresentation(document, window);
