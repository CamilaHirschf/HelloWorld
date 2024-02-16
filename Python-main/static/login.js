function loginUser(username, password) {
    // Simulate a login request and obtain the token from the server
    fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password })
    }).then(response => {
        if (response.ok) {
            return response.json();
        } else {
            throw new Error('Login failed');
        }
    }).then(data => {
        // Store the token in the session storage or cookie
        sessionStorage.setItem('jwtToken', data.access_token);

        // Now make a request to the protected route with the token
        fetch('/dashboard', {
            headers: {
                'Authorization': 'Bearer ' + data.access_token
            }
        }).then(response => {
            if (response.ok) {
                // Handle success, perhaps navigate to the dashboard page
                window.location.href = '/dashboard';
            } else {
                // Handle error
                console.error('Failed to fetch dashboard data');
            }
        });
    }).catch(error => {
        console.error('Error during login:', error);
    });
}
