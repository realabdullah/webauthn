// check if local storage contains a token and if it does, redirect to the dashboard page
if (localStorage.getItem('webauthned'))  window.location.href = 'dashboard.html';

const { browserSupportsWebAuthn, startAuthentication, startRegistration } = SimpleWebAuthnBrowser;
const loginForm = document.querySelector('#login');
const registerForm = document.querySelector('#register');
const loginEmail = document.querySelector('#login #email');
const loginError = document.querySelector('#login .error');
const loginSubmit = document.querySelector('#login #submit');
const registerEmail = document.querySelector('#register #email');
const registerError = document.querySelector('#register .error');
const registerSubmit = document.querySelector('#register #submit');
const loginBtn = document.querySelector('.login-btn');
const registerBtn = document.querySelector('.signup-btn');

const switchForm = (mode) => {
    if (mode === 'login') {
        document.querySelector('.login').style.display = 'block';
        document.querySelector('.register').style.display = 'none';
    } else {
        document.querySelector('.login').style.display = 'none';
        document.querySelector('.register').style.display = 'block';
    }
};

loginBtn.addEventListener('click', () => switchForm('login'));
registerBtn.addEventListener('click', () => switchForm('signup'));

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
        attResp.email = email;
    } catch (error) {
        console.error("Error registering", error);
        registerError.innerHTML = error.message;
        return;
    }

    try {
        const verification = await fetch('/verify-registration-response', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(attResp),
        }).then((response) => response.json());
    
        if (verification.verified) {
            console.log('Verification successful');
            registerError.innerHTML = "Registration successful! You can now login";
            registerError.style.color = 'green';
        } else {
            alert('Verification failed');
        }
    } catch (error) {
        console.error("Error verifying registration", error);
        registerError.innerHTML = error.message;
    }
};

const login = async (email) => {
    const resp = await fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email }),
    });

    let attResp;
    try {
        const options = await resp.json();
        console.log('Authenticator options 3', options);
        if (options.error) throw new Error(options.error);
        attResp = await startAuthentication(options);
        attResp.email = email;
    } catch (error) {
        console.error("Error authenticating", error);
        loginError.innerHTML = error.message;
        return;
    }

    try {
        const verification = await fetch('/verify-login-response', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(attResp),
        }).then((response) => response.json());
    
        if (verification.verified) {
            console.log('Verification successful');
            localStorage.setItem('webauthned', true);
            window.location.href = 'dashboard.html';
        } else {
            alert('Verification failed');
        }
    } catch (error) {
        console.error("Error verifying authentication", error);
        loginError.innerHTML = error.message;
    }
};

if (!browserSupportsWebAuthn()) {
    alert("WebAuthn is not supported in this browser");
}

const stopSubmit = (e) => e.preventDefault();

registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    if (registerEmail.value.trim() === '') registerError.innerHTML= 'Email is required';

   await register(registerEmail.value.trim());
});

loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    if (loginEmail.value.trim() === '') loginError.innerHTML= 'Email is required';

    await login(loginEmail.value.trim());
});

registerEmail.addEventListener('focus', () => {
    registerError.innerHTML = '';
    document.querySelector('#register .email').classList.add('active');
});

registerEmail.addEventListener('blur', () => document.querySelector('#register .email').classList.remove('active'));

loginEmail.addEventListener('focus', () => {
    loginError.innerHTML = '';
    document.querySelector('#login .email').classList.add('active');
});

loginEmail.addEventListener('blur', () => document.querySelector('#login .email').classList.remove('active'));