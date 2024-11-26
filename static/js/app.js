document.addEventListener('DOMContentLoaded', () => {
    const steps = document.querySelectorAll('.form-step');
    const nextButtons = document.querySelectorAll('.next-btn');
    const dropArea = document.getElementById('image-drop-area');
    const fileInput = document.getElementById('image-upload-input');
    const preview = document.getElementById('image-preview');
    const publishBtn = document.getElementById('publish-btn');
    const errorMessage = document.getElementById('error-message');
    const postTitleInput = document.getElementById('post-title');

    let currentStep = 0;

    steps[currentStep].style.display = 'flex';
    steps[currentStep].classList.add('active');

    // Disable the first "Next" button initially
    nextButtons[0].disabled = true;

    // Enable/disable the first "Next" button based on title input
    postTitleInput.addEventListener('input', () => {
        if (postTitleInput.value.length >= 3) {
            nextButtons[0].disabled = false;
        } else {
            nextButtons[0].disabled = true;
        }
    });

    nextButtons.forEach(button => {
        button.addEventListener('click', () => {
            // Only proceed if the button is not disabled
            if (!button.disabled) {
                steps[currentStep].classList.remove('active');
                steps[currentStep].style.opacity = '0';

                setTimeout(() => {
                    steps[currentStep].style.display = 'none';
                    currentStep++;

                    steps[currentStep].style.display = 'flex';

                    setTimeout(() => {
                        steps[currentStep].style.opacity = '1';
                        steps[currentStep].classList.add('active');
                    }, 50);
                }, 500);
            }
        });
    });

    dropArea.addEventListener('dragover', handleDragOver);
    dropArea.addEventListener('drop', handleDrop);
    dropArea.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', handleFileSelect);

    function handleFileSelect(event) {
        const files = event.target.files;
        handleFiles(files);
    }

    function handleDragOver(event) {
        event.preventDefault();
        dropArea.classList.add('drag-over');
    }

    dropArea.addEventListener('dragleave', () => {
        dropArea.classList.remove('drag-over');
    });

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
                        if (img.width >= 256 && img.height >= 256) {
                            preview.innerHTML = `<img src="${e.target.result}" alt="Image preview">`;
                            preview.style.display = 'block';
                            dropArea.style.display = 'none';
                            publishBtn.style.display = 'block';
                            errorMessage.style.display = 'none';
                        } else {
                            errorMessage.style.display = 'block';
                            preview.style.display = 'none';
                            dropArea.style.display = 'flex';
                            publishBtn.style.display = 'none';
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

    preview.addEventListener('click', () => {
        dropArea.style.display = 'flex';
        preview.style.display = 'none';
        publishBtn.style.display = 'none';
        fileInput.click();
    });
});
