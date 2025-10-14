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
