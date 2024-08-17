// ************** Activate one checkbox at a time ************
const activeSwitches = document.querySelectorAll('.switch');


activeSwitches.forEach(switchElement => {
    switchElement.addEventListener('click', function () {
        const checkbox = switchElement.querySelector('#isActive');

        if (checkbox.checked) {
            // If the checkbox is already checked, uncheck it
            checkbox.checked = false;
        } else {
            // If the checkbox is not checked, uncheck all other checkboxes first
            activeSwitches.forEach(otherSwitch => {
                otherSwitch.querySelector('#isActive').checked = false;
            });
            // Then check the current checkbox
            checkbox.checked = true;
        }
    });
});