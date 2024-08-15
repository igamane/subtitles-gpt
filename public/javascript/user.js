// toggle nav bar
const bar = document.querySelector('.menu-toggle');
const sidebar = document.querySelector('.dashboard-sidebar');
const main = document.querySelector('.dashboard-main')
const overlay = document.querySelector('.overlay')

bar.addEventListener('click', () => {
    sidebar.classList.toggle('hide-sidebar');
    main.classList.toggle('extand-main');
    overlay.classList.toggle('show-overlay');
})
overlay.addEventListener('click', () => {
    sidebar.classList.remove('hide-sidebar');
    overlay.classList.remove('show-overlay')
})

// show modale
const addAccessBtn = document.querySelectorAll('.add-access');
const closemodal = document.querySelector('.modal__close');
const modal = document.querySelector('.modal__container');
const overlayr = document.querySelector('.modal-overlay');

addAccessBtn.forEach(b => {
    b.addEventListener('click', function () {
        modal.classList.add('show-modal');
        overlayr.classList.add('show-modal-overlay');
        const userID = b.parentElement.getAttribute('data-userid');
        modal.querySelector('#userId').value = userID;
    })
})
overlayr.addEventListener('click', () => {
    modal.classList.remove('show-modal');
    overlayr.classList.remove('show-modal-overlay');
    modal.querySelector('#userId').value = '';
})
closemodal.addEventListener('click', function () {
    modal.classList.remove('show-modal');
    overlayr.classList.remove('show-modal-overlay');
    modal.querySelector('#userId').value = '';
})

// ============== select ==============
const selected = document.querySelector('.selected');
const selectedP = document.querySelector('.selected p');
const optionsContainer = document.querySelector('.options-container');
const options = document.querySelectorAll('.option label')

selected.addEventListener('click', () => {
	optionsContainer.classList.toggle('activec');
})

options.forEach(o => {
	o.addEventListener('click', () => {
		selectedP.innerHTML = o.innerHTML;
		optionsContainer.classList.remove('activec');
	})
})


// ===== form elements =====
const editModalButton = document.querySelectorAll('.edit-access');
const editClosemodal = document.querySelector('.edit_modal__close');
const editModal = document.querySelector('.edit_modal__container');
const editOverlayr = document.querySelector('.edit_modal-overlay');

editModalButton.forEach(b => {
    b.addEventListener('click', function () {
        const userID = b.parentElement.getAttribute('data-userid');
        fetchUserUsageDetails(userID);
    })
})
editOverlayr.addEventListener('click', () => {
    editModal.classList.remove('show-modal');
    editOverlayr.classList.remove('show-modal-overlay')
})
editClosemodal.addEventListener('click', function () {
    editModal.classList.remove('show-modal');
    editOverlayr.classList.remove('show-modal-overlay');
})

async function fetchUserUsageDetails(id) {
    await fetch(`/user/${id}/usage`)
        .then((response) => response.json())
        .then((data) => {
            // Assuming `modalContent` is the container where you want to append the details
            const modalContent = document.querySelector('.edit-modal__content');
            // Clear existing content
            modalContent.innerHTML = '<h4 class="modal__title">Edit User Access Right</h4>';

            if (!data.data || data.data.length === 0) {
                const mes = document.createElement('p');
                mes.textContent = 'No Access Right is assigned to this user'
                modalContent.appendChild(mes);
            } else {
                data.data.forEach((item, index) => {
                    const formBody = document.createElement('div');
                    formBody.classList.add('form-body');
                    formBody.innerHTML = `
                        <div class="error-container">
                            <div class="input-field">
                                <label for="edit-propertyName-${index}">Prompt Name</label>
                                <input type="text" id="edit-propertyName-${index}" value="${item.name}" class="input" disabled>
                            </div>
                            <div class="errormessage"></div>
                        </div>
                        <div class="error-container">
                            <div class="input-field">
                                <label for="usageLimit-${index}">Usage Limit</label>
                                <input type="number" id="usageLimit-${index}" value="${item.usage}" class="input" disabled>
                            </div>
                            <div class="errormessage"></div>
                        </div>
                        <form action="/admin/usage/delete?_method=Delete" style="margin: auto;" method="post">
                        <input type="text" name="userId" value="${id}" style="display: none;">
                            <input type="text" name="promptId" value="${item.id}" style="display: none;">
                            <button class="btn delete delete-prompt">
                                <span class="material-symbols-outlined">
                                    delete
                                </span>
                            </button>
                        </form>
                    `;
                    // Append the formBody to the modal content
                    modalContent.appendChild(formBody);
                });
            }


            // Display the modal
            editModal.classList.add('show-modal');
            editOverlayr.classList.add('show-modal-overlay');
        })
        .catch((error) => {
            console.error('Error fetching user usage details:', error);
        });
}
