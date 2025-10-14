// app.js - client behavior: show masked IP, set consent cookie
async function fetchIp() {
  try {
    const r = await fetch('/api/my-ip');
    if (!r.ok) throw new Error('Network error');
    const json = await r.json();
    document.getElementById('ip').textContent = json.ip_masked || 'unknown';
  } catch (err) {
    document.getElementById('ip').textContent = 'Could not fetch IP';
    console.error(err);
  }
}

document.getElementById('refresh').addEventListener('click', fetchIp);

document.getElementById('consent-btn').addEventListener('click', async () => {
  try {
    const r = await fetch('/api/consent', { method: 'POST', headers: {'Content-Type':'application/json'} });
    const json = await r.json();
    if (json.success) {
      alert('Consent recorded. Your full IP will be stored for testing on subsequent requests.');
    } else {
      alert('Could not set consent (server error).');
    }
  } catch (err) {
    console.error(err);
    alert('Network error while setting consent.');
  }
});

// initial load
fetchIp();
