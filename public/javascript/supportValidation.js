// =============== signup validation =================== 
const form = document.getElementById('form');
const subject= document.getElementById('subject');
const message = document.querySelector('#message');

form.addEventListener('submit', e => {

	const subjectValue = subject.value.trim();
	const messageValue = message.value.trim();

	if (subjectValue === '') {
		setError(subject, 'Subject is a required field');
		e.preventDefault();
	} else {
		setSuccess(subject)
	}

	if (messageValue === '') {
		setError((message), 'Message is a required field');
		e.preventDefault();
	} else {
		setSuccess(message)
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