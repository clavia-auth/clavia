// Passkeys on Clavia's sign-in origin: the only script this origin runs (docs/design/passkeys.md §8).
//
// It decides nothing. The server writes the options into the page and checks the answer; this
// relays them between the page and the browser's WebAuthn API, using the Level 3 JSON helpers so
// it holds no encoding code. It writes no HTML, only properties and form values, which is what
// lets the page run under Trusted Types with no policy. A browser that cannot make a passkey sees
// the page as it is without script.

const createForm = document.querySelector('form[data-webauthn-create]');

const supported = typeof window.PublicKeyCredential === 'function'
  && typeof PublicKeyCredential.parseCreationOptionsFromJSON === 'function';

if (createForm !== null && supported) {
  const start = createForm.querySelector('[data-webauthn-start]');
  const unsupported = createForm.querySelector('[data-webauthn-unsupported]');
  const failed = createForm.querySelector('[data-webauthn-failed]');

  unsupported.hidden = true;
  start.hidden = false;

  createForm.addEventListener('submit', async (event) => {
    if (createForm.elements.credential.value !== '') {
      return;
    }
    event.preventDefault();
    failed.hidden = true;
    start.disabled = true;

    try {
      const options = PublicKeyCredential.parseCreationOptionsFromJSON(
        JSON.parse(createForm.dataset.webauthnCreate),
      );
      const credential = await navigator.credentials.create({ publicKey: options });
      createForm.elements.credential.value = JSON.stringify(credential.toJSON());
      createForm.submit();
    } catch (error) {
      // Cancelled or timed out: nothing happened, and nothing needs saying.
      if (!(error instanceof DOMException && error.name === 'NotAllowedError')) {
        failed.hidden = false;
      }
      start.disabled = false;
    }
  });
}
