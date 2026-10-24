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
})();
"""
