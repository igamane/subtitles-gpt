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

const imgArea = document.querySelector('.img-area');
const uploadProfile = document.querySelector('.upload-profile');


// ========= Image upload ==========

const inputFile = document.querySelector('#profileImage');

imgArea.addEventListener('click', function () {
    inputFile.click();
})
uploadProfile.addEventListener('click', function () {
    inputFile.click();
})

inputFile.addEventListener('change', function () {
    const image = this.files[0] 
    if (image.size < 10000000) {
        const reader = new FileReader();
        reader.onload = () => {
            const allImg = imgArea.querySelectorAll('img');
            allImg.forEach(item => item.remove());
            const imgUrl = reader.result;
            const img = document.createElement('img');
            img.src = imgUrl;
            imgArea.appendChild(img);
            imgArea.classList.add('active');
            imgArea.dataset.img = image.name;
        }
        reader.readAsDataURL(image);
    } else {
        alert("The image size is more than 10MB");
    }
})


function deleteImage() {
    var image = imgArea.querySelector("img");
    if (image) {
        imgArea.removeChild(image);
    }
}
