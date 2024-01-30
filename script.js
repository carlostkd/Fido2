// FIDO2 registration
async function register() {
    try {
        const response = await fetch('server.php?action=register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
        });

        const resultText = await response.text();

        try {
            const result = JSON.parse(resultText);

            if (result.success) {
                const publicKeyOptions = result.publicKeyOptions;
                const challenge = base64UrlToUint8Array(publicKeyOptions.challenge);

                publicKeyOptions.challenge = challenge;
                publicKeyOptions.user.id = base64UrlToUint8Array(publicKeyOptions.user.id);

                const credential = await navigator.credentials.create({
                    publicKey: publicKeyOptions,
                });

                // Send the credential to the server for validation and storage

                document.getElementById('output').innerHTML = 'Registration successful!';
            } else {
                document.getElementById('output').innerHTML = 'Registration failed. ' + result.message;
            }
        } catch (jsonParseError) {
            console.error('JSON Parse Error during registration:', jsonParseError);
            document.getElementById('output').innerHTML = 'Failed to parse JSON response during registration.';
        }
    } catch (error) {
        console.error('Registration error:', error);
        document.getElementById('output').innerHTML = 'Registration failed.';
    }
}

// FIDO2 authentication
async function authenticate() {
    try {
        const response = await fetch('server.php?action=authenticate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
        });

        const resultText = await response.text();

        try {
            const result = JSON.parse(resultText);

            if (result.success) {
                const publicKeyOptions = result.publicKeyOptions;
                const challenge = base64UrlToUint8Array(publicKeyOptions.challenge);

                publicKeyOptions.challenge = challenge;
                publicKeyOptions.allowCredentials.forEach(cred => {
                    cred.id = base64UrlToUint8Array(cred.id);
                });

                const credential = await navigator.credentials.get({
                    publicKey: publicKeyOptions,
                });

                // Send the credential to the server for validation

                document.getElementById('output').innerHTML = 'Authentication successful!';
            } else {
                document.getElementById('output').innerHTML = 'Authentication failed. ' + result.message;
            }
        } catch (jsonParseError) {
            console.error('JSON Parse Error during authentication:', jsonParseError);
            document.getElementById('output').innerHTML = 'Failed to parse JSON response during authentication.';
        }
    } catch (error) {
        console.error('Authentication error:', error);
        document.getElementById('output').innerHTML = 'Authentication failed.';
    }
}

// base64Url to Uint8Array
function base64UrlToUint8Array(base64Url) {
    const padding = '='.repeat((4 - base64Url.length % 4) % 4);
    const base64 = (base64Url + padding)
        .replace(/\-/g, '+')
        .replace(/_/g, '/');

    const rawData = atob(base64);
    const buffer = new Uint8Array(rawData.length);

    for (let i = 0; i < rawData.length; ++i) {
        buffer[i] = rawData.charCodeAt(i);
    }

    return buffer;
}
