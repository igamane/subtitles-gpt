// =============== login validation =================== 

const form = document.getElementById('form');
const email = document.getElementById('email');
const password = document.getElementById('password');

form.addEventListener('submit', e => {
	// let errmessages = [];

	const emailValue = email.value.trim();
	const passwordValue = password.value.trim();

    if (emailValue === '') {
		setError(email, 'Email is a required field');
		e.preventDefault();
	} else if (!isValidEmail(emailValue)) {
		setError(email, 'The email address you entered is not valid');
		e.preventDefault();
	} else {
		setSuccess(email)
	} 

    if (passwordValue === '') {
		setError(password, 'Password is a required field');
		e.preventDefault();
	} else {
		setSuccess(password);
	} 
});

const setError = (element, message) => {
	const inputControl = element.parentElement.parentElement;
	const errorDisplay = inputControl.querySelector('.errormessage');

	errorDisplay.innerText = message;
	inputControl.classList.add('error');
}
const setSuccess = element => {
	const inputControl = element.parentElement.parentElement;
	const errorDisplay = inputControl.querySelector('.errormessage');

	errorDisplay.innerText = '';
	inputControl.classList.remove('error');
};


const isValidEmail = email => {
	const re = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
	return re.test(String(email).toLowerCase());
}