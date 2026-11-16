// Progressive enhancement: a reveal toggle for password fields.
// Loaded with defer and served from /static so it satisfies the strict CSP.
// It does not change the submit behaviour; the form still works without it.
(function () {
  'use strict';
  document.querySelectorAll('button.reveal').forEach(function (button) {
    var target = document.getElementById(button.dataset.target);
    if (!target) return;
    var show = button.querySelector('.show');
    var hide = button.querySelector('.hide');
    button.addEventListener('click', function () {
      var revealing = target.type === 'password';
      target.type = revealing ? 'text' : 'password';
      button.setAttribute('aria-pressed', String(revealing));
      if (show && hide) {
        show.classList.toggle('visually-hidden', revealing);
        hide.classList.toggle('visually-hidden', !revealing);
      }
      target.focus();
    });
  });

  // Recovery token handling: the reset link carries the token in the URL
  // fragment (#t=...), which is never sent to the server or any proxy and
  // cannot leak through a Referrer header. Read it, clear it from the address
  // bar immediately, and move it into a hidden field so it is submitted in the
  // request body instead. This is defence in depth; the server never requires
  // the token in the path.
  var match = window.location.hash.match(/(?:^#|[&#])t=([^#&]+)/);
  var tokenInput = document.getElementById('token');
  if (match) {
    var token = match[1];
    history.replaceState(null, '', window.location.pathname + window.location.search);
    if (tokenInput) {
      tokenInput.value = token;
    }
  }
  var details = document.getElementById('recovery-details');
  var csrf = document.querySelector('#recovery-form input[name="csrf"]');
  function showDetails() {
    if (!details || !tokenInput || !csrf || !tokenInput.value) return;
    details.hidden = true;
    var checkedToken = tokenInput.value;
    var body = new URLSearchParams({csrf: csrf.value, token: checkedToken});
    fetch('/reset/details', {method: 'POST', body: body, credentials: 'same-origin'})
      .then(function (response) { return response.ok ? response.json() : null; })
      .then(function (data) {
        if (tokenInput.value !== checkedToken || !data ||
            typeof data.account !== 'string' || typeof data.destination !== 'string' ||
            (data.channel !== 'email' && data.channel !== 'telegram')) return;
        document.getElementById('recovery-account').textContent = data.account;
        var label = data.channel === 'email' ? details.dataset.emailLabel : details.dataset.telegramLabel;
        document.getElementById('recovery-destination').textContent = label + ' · ' + data.destination;
        var emailRow = document.getElementById('recovery-associated-email-row');
        emailRow.hidden = typeof data.associated_email !== 'string';
        document.getElementById('recovery-associated-email').textContent = data.associated_email || '';
        details.hidden = false;
      }).catch(function () { /* Details are optional; the form remains usable. */ });
  }
  if (tokenInput) {
    tokenInput.addEventListener('input', function () { if (details) details.hidden = true; });
    tokenInput.addEventListener('change', showDetails);
    showDetails();
  }
})();
