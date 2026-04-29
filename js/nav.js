(function () {
  function initNav() {
    var navInner = document.querySelector('.site-nav .nav-inner');
    if (!navInner) return;

    var navLinks = navInner.querySelector('.nav-links');
    if (!navLinks) return;

    if (!navLinks.id) navLinks.id = 'site-nav-links';

    if (navInner.querySelector('.nav-mobile-toggle')) return;

    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'nav-mobile-toggle';
    btn.setAttribute('aria-label', 'Toggle navigation menu');
    btn.setAttribute('aria-expanded', 'false');
    btn.setAttribute('aria-controls', navLinks.id);
    btn.innerHTML = '<span aria-hidden="true">&#9776;</span>';

    btn.addEventListener('click', function () {
      var isOpen = navLinks.classList.toggle('open');
      btn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
      btn.innerHTML = isOpen
        ? '<span aria-hidden="true">&times;</span>'
        : '<span aria-hidden="true">&#9776;</span>';
    });

    document.addEventListener('click', function (e) {
      if (!navInner.contains(e.target) && navLinks.classList.contains('open')) {
        navLinks.classList.remove('open');
        btn.setAttribute('aria-expanded', 'false');
        btn.innerHTML = '<span aria-hidden="true">&#9776;</span>';
      }
    });

    navInner.appendChild(btn);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initNav);
  } else {
    initNav();
  }
})();
