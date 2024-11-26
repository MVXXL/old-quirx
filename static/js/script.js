document.getElementById('submitBtn').addEventListener('click', function() {
    const report = document.getElementById('report').value;
    if (report) {
        fetch('/submit_report', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ report: report })
        })
        .then(response => response.json())
        .then(data => {
            document.getElementById('response').innerText = data.message;
            document.getElementById('report').value = '';
        })
        .catch(error => {
            document.getElementById('response').innerText = 'An error occurred. Please try again.';
        });
    } else {
        document.getElementById('response').innerText = 'Please enter a report before submitting.';
    }
});

document.addEventListener("DOMContentLoaded", function() {
    const dropArea = document.getElementById('image-drop-area');
    const fileInput = document.getElementById('image-upload-input');
    const preview = document.getElementById('image-preview');
    const errorMessage = document.getElementById('error-message');

    dropArea.addEventListener('click', () => fileInput.click());

    fileInput.addEventListener('change', handleFileSelect);
    dropArea.addEventListener('dragover', handleDragOver);
    dropArea.addEventListener('drop', handleDrop);

    function handleFileSelect(event) {
        const files = event.target.files;
        handleFiles(files);
    }

    function handleDragOver(event) {
        event.preventDefault();
        dropArea.classList.add('drag-over');
    }

    function handleDrop(event) {
        event.preventDefault();
        dropArea.classList.remove('drag-over');
        const files = event.dataTransfer.files;
        handleFiles(files);
    }

    function handleFiles(files) {
        if (files.length > 0) {
            const file = files[0];
            if (file.type.startsWith('image/')) {
                const reader = new FileReader();
                reader.onload = function(e) {
                    const img = new Image();
                    img.onload = function() {
                        if (img.width >= 512 && img.height >= 512) {
                            preview.innerHTML = `<img src="${e.target.result}" alt="Image preview">`;
                            preview.style.display = 'block';
                            errorMessage.style.display = 'none';
                        } else {
                            errorMessage.style.display = 'block';
                            preview.style.display = 'none';
                            setTimeout(() => {
                                errorMessage.style.display = 'none';
                            }, 3000);
                        }
                    };
                    img.src = e.target.result;
                };
                reader.readAsDataURL(file);
            } else {
                alert('Please upload an image file.');
            }
        }
    }
});
