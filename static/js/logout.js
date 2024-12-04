document.getElementById('logoutBtn').addEventListener('click', function() {
    const token = localStorage.getItem('token');  // Or wherever you store the token
    fetch('/api/logout/', {
        method: 'POST',
        headers: {
            'Authorization': `Token ${token}`,  // Include token in the header
            'Content-Type': 'application/json',
        }
    })
    .then(response => response.json())
    .then(data => {
        console.log('Logged out:', data);
        // Optionally, redirect to login page after logout
        window.location.href = '/login/';
    })
    .catch(error => {
        console.error('Error logging out:', error);
    });
});
