// =============== login validation =================== 

const form = document.getElementById('form');
const password = document.getElementById('password');
const password2 = document.getElementById('confirm');

form.addEventListener('submit', e => {
	const passwordValue = password.value.trim();
	const password2Value = password2.value.trim();
    if (passwordValue === '') {
		setError(password, 'Password is a required field');
		e.preventDefault();
	} else if (passwordValue.length < 5) {
		setError(password, 'Use 5 or more characters for the password')
		e.preventDefault();
	} else {
		setSuccess(password);
	}

	if (password2Value === '') {
		setError(password2, 'Please confirm the password');
		e.preventDefault();
	} else if (password2Value !== passwordValue) {
		setError(password2, "The two passwords you entered do not match. Please try again");
		e.preventDefault();
	} else {
		setSuccess(password2);
	}
});

const setError = (element, message) => {
	const inputControl = element.parentElement.parentElement.parentElement;
	const errorDisplay = inputControl.querySelector('.errormessage');

	errorDisplay.innerText = message;
	inputControl.classList.add('error');
}
const setSuccess = element => {
	const inputControl = element.parentElement.parentElement.parentElement;
	const errorDisplay = inputControl.querySelector('.errormessage');

	errorDisplay.innerText = '';
	inputControl.classList.remove('error');
};
