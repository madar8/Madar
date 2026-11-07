let installPrompt;
const standalone = matchMedia('(display-mode: standalone)');
function updateInstallAvailability() {
  document.documentElement.toggleAttribute('data-installed', standalone.matches || navigator.standalone === true);
}
updateInstallAvailability();
standalone.addEventListener?.('change', updateInstallAvailability);
window.addEventListener('beforeinstallprompt', event => {
  event.preventDefault();
  installPrompt = event;
});
window.addEventListener('appinstalled', () => {
  installPrompt = undefined;
  document.documentElement.setAttribute('data-installed', '');
});
document.addEventListener('click', async event => {
  if (!event.target.closest('[data-install]')) return;
  if (installPrompt) {
    const prompt = installPrompt;
    installPrompt = undefined;
    try {
      await prompt.prompt();
      return;
    } catch {
      // Show the browser menu instructions when the native prompt is unavailable.
    }
  }
  document.querySelector('#install-dialog').showModal();
});
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js').catch(() => {
    // The regular web experience is available even if registration is blocked.
  });
}
