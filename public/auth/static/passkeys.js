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
// the form's `credential` field, by the form's own POST. A `get` form marked
// `data-webauthn-conditional` also offers its passkeys in the address field's autofill
// (conditional mediation), and stops offering them once the person does anything else.

const ceremonies = [
  {
    selector: 'form[data-webauthn-create]',
    supported: () => typeof PublicKeyCredential.parseCreationOptionsFromJSON === 'function',
    options: (form) => PublicKeyCredential.parseCreationOptionsFromJSON(JSON.parse(form.dataset.webauthnCreate)),
    run: (publicKey, extra) => navigator.credentials.create({ publicKey, ...extra }),
  },
  {
    selector: 'form[data-webauthn-get]',
    supported: () => typeof PublicKeyCredential.parseRequestOptionsFromJSON === 'function',
    options: (form) => PublicKeyCredential.parseRequestOptionsFromJSON(JSON.parse(form.dataset.webauthnGet)),
    run: (publicKey, extra) => navigator.credentials.get({ publicKey, ...extra }),
  },
];

const webAuthn = typeof window.PublicKeyCredential === 'function';

const answer = (form, credential) => {
  form.elements.credential.value = JSON.stringify(credential.toJSON());
  form.submit();
};

const quiet = (error) => error instanceof DOMException
  && (error.name === 'NotAllowedError' || error.name === 'AbortError');

for (const ceremony of ceremonies) {
  const form = document.querySelector(ceremony.selector);
  if (form === null || !webAuthn || !ceremony.supported()) {
    continue;
  }
  const start = form.querySelector('[data-webauthn-start]');
  const unsupported = form.querySelector('[data-webauthn-unsupported]');
  const failed = form.querySelector('[data-webauthn-failed]');
  let conditional = null;

  if (unsupported !== null) {
    unsupported.hidden = true;
  }
  start.hidden = false;

  const stopOffering = () => {
    if (conditional !== null) {
      conditional.abort();
      conditional = null;
    }
  };

  form.addEventListener('submit', async (event) => {
    if (form.elements.credential.value !== '') {
      return;
    }
    event.preventDefault();
    stopOffering();
    failed.hidden = true;
    start.disabled = true;

    try {
      answer(form, await ceremony.run(ceremony.options(form), {}));
    } catch (error) {
      // Cancelled or timed out: nothing happened, and nothing needs saying.
      if (!quiet(error)) {
        failed.hidden = false;
      }
      start.disabled = false;
    }
  });

  if ('webauthnConditional' in form.dataset
    && typeof PublicKeyCredential.isConditionalMediationAvailable === 'function') {
    // Any other form on the page means the person chose another way in.
    for (const other of document.querySelectorAll('form')) {
      if (other !== form) {
        other.addEventListener('submit', stopOffering);
      }
    }
    PublicKeyCredential.isConditionalMediationAvailable().then(async (available) => {
      if (!available) {
        return;
      }
      conditional = new AbortController();
      try {
        answer(form, await ceremony.run(ceremony.options(form), {
          mediation: 'conditional',
          signal: conditional.signal,
        }));
      } catch (error) {
        if (!quiet(error)) {
          failed.hidden = false;
        }
      }
    });
  }
}
