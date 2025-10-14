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
