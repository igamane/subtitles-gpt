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

function handleUpload(fileType) {
    let fileInput;

    if (fileType === 'html') {
        fileInput = document.getElementById('html-file');
    } else if (fileType === 'excel') {
        fileInput = document.getElementById('excel-file');
    }

    // Trigger file input click event
    fileInput.click();

    // Handle file input change event
    fileInput.onchange = function() {
        const file = fileInput.files[0];
        if (!file) return;

        // Create FormData to send the file to the server
        const formData = new FormData();
        formData.append('file', file);

        // Hide the upload section and show the progress bar
        document.getElementById('upload-section').style.display = 'none';
        document.getElementById('progress-container').style.display = 'block';

        // API endpoint based on file type
        const apiUrl = fileType === 'html' ? '/html-file' : '/excel-file';

        // Listen for progress updates via SSE
        const progressSource = new EventSource('/progress');
        progressSource.onmessage = function(event) {
            // Parse the progress data from the server
            const [processedLines, totalLines] = event.data.split('/').map(Number);
            const progressPercentage = (processedLines / totalLines) * 100;

            // Update the progress bar and text
            document.getElementById('progress-bar').style.width = `${progressPercentage}%`;
            document.getElementById('progress-text').textContent = `Processing ${processedLines} out of ${totalLines} lines...`;
        };

        // Send file to the server via fetch API
        fetch(apiUrl, {
            method: 'POST',
            body: formData,
        })
        .then(response => response.json())
        .then(data => {
            console.log(data); // Handle the server response here

            // Hide progress bar and show the processing complete message
            document.getElementById('progress-text').textContent = 'Processing complete! You can now download your file.';
            document.getElementById('progress-bar').style.backgroundColor = '#28a745'; // Change color to green

            // Show the download button with the correct file URL
            document.getElementById('download-button').href = data.fileUrl;
            document.getElementById('download-section').style.display = 'flex';

            // Close the progress event source
            progressSource.close();
        })
        .catch(error => {
            console.error('Error:', error);
            // Handle errors here
            document.getElementById('progress-text').textContent = 'Error processing file. Please try again.';
            document.getElementById('progress-bar').style.backgroundColor = '#dc3545'; // Change color to red

            // Close the progress event source
            progressSource.close();
        });
    };
}
