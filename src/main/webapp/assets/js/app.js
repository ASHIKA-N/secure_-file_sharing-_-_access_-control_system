document.addEventListener('submit', function (event) {
  const message = event.target.dataset.confirm;
  if (message && !window.confirm(message)) event.preventDefault();
});
const viewerStatus = document.querySelector('[data-view-expiry]');
if (viewerStatus) {
  const updateExpiry = () => {
    const remaining = Math.max(0, Math.ceil((Date.parse(viewerStatus.dataset.viewExpiry) - Date.now()) / 1000));
    document.getElementById('remaining-time').textContent = remaining ? `${Math.floor(remaining / 60)}m ${remaining % 60}s remaining` : 'Session expired. New resource requests will be denied.';
  };
  updateExpiry();
  setInterval(updateExpiry, 1000);
}
