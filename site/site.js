// Shared behaviour: theme switch, doc-page conveniences, and the landing page's step tabs.
// Everything here is an enhancement. Without it every step and every list stays visible.
(function () {
  var d = document.documentElement;
  var theme = document.getElementById('theme');
  if (theme) theme.onclick = function () {
    var dark = d.dataset.theme ? d.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme:dark)').matches;
    d.dataset.theme = dark ? 'light' : 'dark';
    try { localStorage.setItem('pl-theme', d.dataset.theme); } catch (e) {}
  };

  // On a phone the two lists start closed so the page's own text comes first.
  if (matchMedia('(max-width:820px)').matches) {
    document.querySelectorAll('details[data-phone-closed]').forEach(function (el) { el.removeAttribute('open'); });
  }

  // A long contents list would push the document off the first screen, so it starts closed.
  document.querySelectorAll('details.toc').forEach(function (el) {
    if (el.querySelectorAll('a').length > 24) el.removeAttribute('open');
  });

  // The copy button sits in the corner of a wrapper, so it stays put while the code scrolls.
  if (navigator.clipboard) document.querySelectorAll('article pre').forEach(function (p) {
    if (p.closest('figure')) return;
    var w = document.createElement('div'), b = document.createElement('button');
    w.className = 'cb';
    p.parentNode.insertBefore(w, p);
    w.appendChild(p);
    b.type = 'button'; b.className = 'copy'; b.textContent = 'copy';
    b.onclick = function () {
      navigator.clipboard.writeText(p.textContent).then(function () {
        b.textContent = 'copied';
        setTimeout(function () { b.textContent = 'copy'; }, 1500);
      });
    };
    w.appendChild(b);
  });

  var steppers = document.querySelectorAll('.stepper');
  if (steppers.length) d.classList.add('js');
  steppers.forEach(function (root, ri) {
    var steps = [].slice.call(root.querySelectorAll('.stage>li')), bar = document.createElement('div');
    bar.className = 'tabs'; bar.setAttribute('role', 'tablist'); bar.setAttribute('aria-label', root.dataset.name + 's');
    var keys = { ArrowRight: 1, ArrowLeft: -1 };
    var btns = steps.map(function (li, i) {
      var b = document.createElement('button');
      b.type = 'button'; b.textContent = li.dataset.t; b.id = 't' + ri + '-' + i;
      b.setAttribute('role', 'tab'); li.id = 'p' + ri + '-' + i; li.setAttribute('role', 'tabpanel');
      b.setAttribute('aria-controls', li.id); li.setAttribute('aria-labelledby', b.id);
      b.onclick = function () { show(i); };
      b.onkeydown = function (e) {
        var n = e.key === 'Home' ? 0 : e.key === 'End' ? steps.length - 1 : keys[e.key] ? i + keys[e.key] : null;
        if (n === null) return;
        e.preventDefault();
        n = (n + steps.length) % steps.length;
        show(n); btns[n].focus();
      };
      bar.appendChild(b);
      return b;
    });
    root.insertBefore(bar, root.firstChild);
    root.querySelector('.stage').setAttribute('role', 'presentation');
    function show(n) {
      steps.forEach(function (li, i) {
        var on = i === n;
        if (on) li.removeAttribute('data-off'); else li.setAttribute('data-off', '');
        btns[i].setAttribute('aria-selected', on); btns[i].tabIndex = on ? 0 : -1;

        // Restarting the block's animation makes the move visible on each step change.
        var blk = li.querySelector('.blk');
        if (on && blk) { blk.style.animation = 'none'; void blk.offsetWidth; blk.style.animation = ''; }
      });
    }
    show(0);
  });
})();
