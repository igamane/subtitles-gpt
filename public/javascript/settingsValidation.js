// =============== signup validation =================== 
const infoForm = document.getElementById('info-form');
const passwordForm = document.getElementById('password-form');
const firstnameinput = document.getElementById('firstname');
const lastnameinput = document.getElementById('lastname');
const email = document.getElementById('email');
const oldPassword = document.getElementById('old-password');
const password = document.getElementById('new-password');
const password2 = document.getElementById('confirm-password');
const phoneNumber = document.getElementById('phoneNumber');


infoForm.addEventListener('submit', e => {

	const firstnameValue = firstnameinput.value.trim();
	const lastnameValue = lastnameinput.value.trim();
	const emailValue = email.value.trim();
	const phoneNumberValue = phoneNumber.value.trim();


	if (firstnameValue === '') {
		setError(firstnameinput, 'The first name is a required field');
		e.preventDefault();
	} else {
		setSuccess(firstnameinput)
	}
	if (lastnameValue === '') {
		setError(lastnameinput, 'The last name is a required field');
		e.preventDefault();
	} else { 
		setSuccess(lastnameinput)
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

	if (phoneNumberValue === '') {
		setError(phoneNumber, 'Phone number is a required field');
		e.preventDefault();
	} else if (isNaN(phoneNumberValue)) {
		setError(phoneNumber, 'Please enter valid information');
		e.preventDefault();
	} else if (phoneNumberValue.length < 9) { 
		setError(phoneNumber, 'Please enter valid information');
		e.preventDefault();
	} else if (phoneNumberValue.length > 14) {
		setError(phoneNumber, 'Please enter valid information');
		e.preventDefault();
	} else {
		setSuccess(phoneNumber);
	}
});

passwordForm.addEventListener('submit', e => {

	const oldPasswordValue = oldPassword.value.trim();
	const passwordValue = password.value.trim();
	const password2Value = password2.value.trim();

	if (oldPasswordValue === '') {
		setError(oldPassword, 'Password is a required field');
		e.preventDefault();
	} else if (oldPasswordValue.length < 5) {
		setError(oldPassword, 'Use 5 or more characters for the password')
		e.preventDefault();
	} else {
		setSuccess(oldPassword);
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
		e.preventDefault();
	} else if (password2Value !== passwordValue) {
		setError(password2, "The two passwords you entered do not match. Please try again");
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
