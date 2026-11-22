// Passkeys on Clavia's sign-in origin: the only script this origin runs (docs/design/passkeys.md §8).
//
// It decides nothing. The server writes the options into the page and checks the answer; this
// relays them between the page and the browser's WebAuthn API, using the Level 3 JSON helpers so
// it holds no encoding code. It writes no HTML, only properties and form values, which is what
// lets the page run under Trusted Types with no policy. A browser that cannot use a passkey sees
// the page as it is without script.
//
// Two kinds of form: `data-webauthn-create` makes a passkey (`navigator.credentials.create()`),
// `data-webauthn-get` uses one (`navigator.credentials.get()`). Either way the answer goes back in
// the form's `credential` field, by the form's own POST.

const ceremonies = [
  {
    selector: 'form[data-webauthn-create]',
    supported: () => typeof PublicKeyCredential.parseCreationOptionsFromJSON === 'function',
    options: (form) => PublicKeyCredential.parseCreationOptionsFromJSON(JSON.parse(form.dataset.webauthnCreate)),
    run: (publicKey) => navigator.credentials.create({ publicKey }),
  },
  {
    selector: 'form[data-webauthn-get]',
    supported: () => typeof PublicKeyCredential.parseRequestOptionsFromJSON === 'function',
    options: (form) => PublicKeyCredential.parseRequestOptionsFromJSON(JSON.parse(form.dataset.webauthnGet)),
    run: (publicKey) => navigator.credentials.get({ publicKey }),
  },
];

const webAuthn = typeof window.PublicKeyCredential === 'function';

for (const ceremony of ceremonies) {
  const form = document.querySelector(ceremony.selector);
  if (form === null || !webAuthn || !ceremony.supported()) {
    continue;
  }
  const start = form.querySelector('[data-webauthn-start]');
  const unsupported = form.querySelector('[data-webauthn-unsupported]');
  const failed = form.querySelector('[data-webauthn-failed]');

  if (unsupported !== null) {
    unsupported.hidden = true;
  }
  start.hidden = false;

  form.addEventListener('submit', async (event) => {
    if (form.elements.credential.value !== '') {
      return;
    }
    event.preventDefault();
    failed.hidden = true;
    start.disabled = true;

    try {
      const credential = await ceremony.run(ceremony.options(form));
      form.elements.credential.value = JSON.stringify(credential.toJSON());
      form.submit();
    } catch (error) {
      // Cancelled or timed out: nothing happened, and nothing needs saying.
      if (!(error instanceof DOMException && error.name === 'NotAllowedError')) {
        failed.hidden = false;
      }
      start.disabled = false;
    }
  });
}
