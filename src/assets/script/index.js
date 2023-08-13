// check if local storage contains a token and if it does, redirect to the dashboard page
if (localStorage.getItem('webauthned'))  window.location.href = 'dashboard.html';

const { browserSupportsWebAuthn, startAuthentication, startRegistration } = SimpleWebAuthnBrowser;

const getAuthOptions = async () => {
    fetch("/generate-registration-options")
        .then((response) => response.json())
        .then((options) => {
            console.log("Authenticator options", options);
            startAuthentication(options, true)
                .then(async (response) => {
                    console.log("Authenticator response", response);
                    const verification = await fetch("/verify-registration-response", {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json",
                        },
                        body: JSON.stringify(response),
                    }).then((response) => response.json());
                    console.log("Verification", verification);
                    if (verification.verified) {
                        console.log("Verification successful")
                        window.location.href = "dashboard.html";
                    } else {
                        alert("Verification failed");
                    }
                });
        });
};

const register = async (email) => {
    const resp = await fetch('/generate-registration-options', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email }),
    });

    let attResp;
    try {
        const options = await resp.json();
        console.log('Authenticator options 2', options);
        attResp = await startRegistration(options);
    } catch (error) {
        console.error("Error registering", error);
        return;
    }

    const verification = await fetch('/verify-registration-response', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(attResp),
    }).then((response) => response.json());

    if (verification.verified) {
        console.log('Verification successful');
        window.location.href = 'dashboard.html';
    } else {
        alert('Verification failed');
    }
};

if (!browserSupportsWebAuthn()) {
    alert("WebAuthn is not supported in this browser");
} else {
    getAuthOptions();
}

// const stopeSubmit = (e) => e.preventDefault();

const form = document.querySelector('form');
const email = document.querySelector('#email');
const error = document.querySelector('.error');
const submit = document.querySelector('#submit');

form.addEventListener('submit', async (e) => {
    e.preventDefault();

    if (email.value.trim() === '') error.textContent = 'Email is required';

   await register(email.value.trim());
});

email.addEventListener('focus', () => {
    error.textContent = '';
    document.querySelector('.email').classList.add('active');
});

email.addEventListener('blur', () => document.querySelector('.email').classList.remove('active'));