// redirect to home page if local storage does not contain a token
if (!localStorage.getItem('webauthned')) window.location.href = 'index.html';