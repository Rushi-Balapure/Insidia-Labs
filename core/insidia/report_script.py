"""Small, dependency-free interactions embedded in offline reports."""

REPORT_SCRIPT = """
(() => {
  const pages = Array.from(document.querySelectorAll('.report-page'));
  const requested = new URLSearchParams(location.search).get('page') || location.hash.slice(1);
  const selected = pages.some(page => page.dataset.page === requested) ? requested : 'summary';
  for (const page of pages) page.hidden = page.dataset.page !== selected;
  for (const link of document.querySelectorAll('[data-page-link]')) {
    if (link.dataset.pageLink === selected) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  }
  const tooltip = document.getElementById('report-tooltip');
  if (!tooltip) return;
  let active = null;
  const suppressed = new WeakSet();
  function hideTooltip() {
    if (active) active.removeAttribute('aria-describedby');
    active = null;
    tooltip.hidden = true;
  }
  function showTooltip(target, event) {
    if (suppressed.has(target)) return;
    if (active && active !== target) active.removeAttribute('aria-describedby');
    active = target;
    tooltip.textContent = target.dataset.tooltip;
    tooltip.hidden = false;
    target.setAttribute('aria-describedby', tooltip.id);
    const bounds = target.getBoundingClientRect();
    const x = event ? event.clientX : bounds.left + bounds.width / 2;
    const y = event ? event.clientY : bounds.bottom;
    const left = Math.max(8, Math.min(innerWidth - tooltip.offsetWidth - 8, x + 12));
    const top = Math.max(8, Math.min(innerHeight - tooltip.offsetHeight - 8, y + 16));
    tooltip.style.left = `${left}px`;
    tooltip.style.top = `${top}px`;
  }
  for (const target of document.querySelectorAll('[data-tooltip]')) {
    target.addEventListener('mouseenter', event => {
      suppressed.delete(target);
      showTooltip(target, event);
    });
    target.addEventListener('mousemove', event => showTooltip(target, event));
    target.addEventListener('mouseleave', () => {
      if (document.activeElement !== target) hideTooltip();
    });
    target.addEventListener('focus', () => {
      suppressed.delete(target);
      showTooltip(target);
    });
    target.addEventListener('blur', hideTooltip);
    target.addEventListener('click', event => showTooltip(target, event));
  }
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && active) {
      suppressed.add(active);
      hideTooltip();
    }
  });
  document.addEventListener('pointerdown', event => {
    if (active && !active.contains(event.target)) hideTooltip();
  });
  addEventListener('scroll', hideTooltip, {passive: true, capture: true});
})();
"""
