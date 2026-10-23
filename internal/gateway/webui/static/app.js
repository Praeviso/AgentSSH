// Buttons with data-confirm ask before their form is sent.
document.addEventListener('submit', (event) => {
  const button = event.submitter;
  const message = button && button.dataset.confirm;
  if (message && !window.confirm(message)) {
    event.preventDefault();
  }
});
