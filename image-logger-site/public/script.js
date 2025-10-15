// Handle privacy modal
document.getElementById('privacy-link').addEventListener('click', (e) => {
    e.preventDefault();
    document.getElementById('privacy-modal').style.display = 'block';
});

document.querySelector('.close').addEventListener('click', () => {
    document.getElementById('privacy-modal').style.display = 'none';
});

window.onclick = (e) => {
    if (e.target === document.getElementById('privacy-modal')) {
        document.getElementById('privacy-modal').style.display = 'none';
    }
};
// script.js (Frontend)
window.addEventListener('load', () => {
  // Automatically log visitor
  fetch(https://ip-store-site.onrender.com/api/log', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path: window.location.pathname }),
  }).catch((err) => console.warn('IP log failed:', err));
});
// frontend auto-log snippet - call on page load
(function () {
  const BACKEND_URL = 'https://YOUR_BACKEND_URL.onrender.com'; // <-- replace with your deployed backend URL

  async function sendLog() {
    try {
      await fetch(`${BACKEND_URL}/api/log`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        // send minimal data — backend will obtain the client IP itself
        body: JSON.stringify({ path: window.location.pathname })
      });
    } catch (e) {
      // non-fatal: logging failure shouldn't break UX
      console.warn('Logging failed', e);
    }
  }

  window.addEventListener('load', () => {
    // Small delay helps ensure CSP/other loads complete
    setTimeout(sendLog, 200);
  });
})();
