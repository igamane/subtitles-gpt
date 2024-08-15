// ============== select ==============
const optionsContainer = document.querySelector('.options-container');
const options = document.querySelectorAll('.option label')

// =============== signup validation =================== 
const form = document.getElementById('form');
const firstNameinput = document.getElementById('firstname');
const lastNameinput = document.getElementById('lastname');
const email = document.getElementById('email');
const password = document.getElementById('password');
const password2 = document.getElementById('password2');
const phoneNumber = document.getElementById('phoneNumber');

form.addEventListener('submit', e => {

	const firstNameValue = firstNameinput.value.trim();
	const lastNameValue = lastNameinput.value.trim();
	const emailValue = email.value.trim();
	const passwordValue = password.value.trim();
	const password2Value = password2.value.trim();
	const phoneNumberValue = phoneNumber.value.trim();


	if (firstNameValue === '') {
		setError(firstNameinput, 'The first name is a required field');
		e.preventDefault();
	} else {
		setSuccess(firstNameinput)
	}
	if (phoneNumberValue === '') {
		setError(phoneNumber, 'The phone number is a required field');
		e.preventDefault();
	} else {
		setSuccess(phoneNumber)
	}

	if (lastNameValue === '') {
		setError(lastNameinput, 'The last name is a required field');
		e.preventDefault();
	} else if (lastNameValue.length < 2) { 
		setError(lastNameinput, 'Please enter valid information');
		e.preventDefault();
	} else {
		setSuccess(lastNameinput)
	}

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
	} else if (passwordValue.length < 5) {
		setError(password, 'Use 5 or more characters for the password')
		e.preventDefault();
	} else { 
		setSuccess(password);
	}

	if (password2Value === '') {
		setError(password2, 'Please confirm the password');
		// errmessages.push('1');
		e.preventDefault();
	} else if (password2Value !== passwordValue) {
		setError(password2, "The two passwords you entered do not match. Please try again");
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