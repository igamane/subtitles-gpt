// =============== login validation =================== 

const form = document.getElementById('form');
const password = document.getElementById('password');
const confirmPassword = document.getElementById('confirmPassword');

form.addEventListener('submit', e => {
	// let errmessages = [];

	const passwordValue = password.value.trim();
	const confirmPasswordValue = confirmPassword.value.trim();

    if (passwordValue === '') {
		setError(password, 'Password is a required field');
		e.preventDefault();
	} else if (passwordValue.length < 5) {
		setError(password, 'Use 5 or more characters for the password')
		e.preventDefault();
	} else { 
		setSuccess(password);
	}

    if (confirmPasswordValue === '') {
		setError(confirmPassword, 'Please confirm the password');
		// errmessages.push('1');
		e.preventDefault();
	} else if (confirmPasswordValue !== passwordValue) {
		setError(confirmPassword, "The two passwords you entered do not match. Please try again");
		// errmessages.push('1');
		e.preventDefault();
	} else {
		setSuccess(password2);
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