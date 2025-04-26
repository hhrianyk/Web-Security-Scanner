document.addEventListener('DOMContentLoaded', function() {
    // Form submit handler
    const startScanBtn = document.getElementById('start-scan');
    const urlInput = document.getElementById('url');
    const consentCheckbox = document.getElementById('consent');
    const scanForm = document.getElementById('scan-form');
    const scanProgress = document.getElementById('scan-progress');
    const scanStatus = document.getElementById('scan-status');
    const progressBar = document.getElementById('progress-bar');
    const scanLogs = document.getElementById('scan-logs');
    const viewReportBtn = document.getElementById('view-report');
    
    // Current scan data
    let currentScanId = null;
    let statusCheckInterval = null;
    
    if (startScanBtn) {
        startScanBtn.addEventListener('click', function() {
            // Basic validation
            if (!urlInput.value) {
                showAlert('Please enter a URL to scan', 'danger');
                return;
            }
            
            if (!consentCheckbox.checked) {
                showAlert('You must confirm that you have permission to scan this site', 'danger');
                return;
            }
            
            // Start scan
            startScan(urlInput.value);
        });
    }
    
    function startScan(url) {
        const formData = new FormData();
        formData.append('url', url);
        formData.append('consent', 'true');
        
        fetch('/scan', {
            method: 'POST',
            body: formData
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.error || 'An error occurred');
                });
            }
            return response.json();
        })
        .then(data => {
            currentScanId = data.scan_id;
            
            // Show progress UI
            scanForm.style.display = 'none';
            scanProgress.style.display = 'block';
            scanStatus.textContent = 'Initializing scan...';
            progressBar.style.width = '0%';
            scanLogs.textContent = '';
            
            // Start polling for updates
            statusCheckInterval = setInterval(checkScanStatus, 2000);
        })
        .catch(error => {
            showAlert(error.message, 'danger');
        });
    }
    
    function checkScanStatus() {
        if (!currentScanId) return;
        
        fetch(`/scan/${currentScanId}/status`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to get scan status');
            }
            return response.json();
        })
        .then(data => {
            // Update UI with status information
            scanStatus.textContent = data.status;
            progressBar.style.width = `${data.progress}%`;
            progressBar.setAttribute('aria-valuenow', data.progress);
            
            // Update logs
            scanLogs.textContent = data.logs.join('\n');
            scanLogs.scrollTop = scanLogs.scrollHeight; // Auto-scroll to bottom
            
            // If scan is completed or failed
            if (data.status === 'Completed' || data.status === 'Failed') {
                clearInterval(statusCheckInterval);
                
                // Show view report button
                viewReportBtn.style.display = 'inline-block';
                viewReportBtn.href = `/scan/${currentScanId}/report`;
                
                // Change progress bar color based on status
                if (data.status === 'Completed') {
                    progressBar.classList.remove('bg-primary');
                    
                    // Determine color based on vulnerabilities found
                    if (data.vulnerabilities && data.vulnerabilities.length > 0) {
                        progressBar.classList.add('bg-warning');
                    } else {
                        progressBar.classList.add('bg-success');
                    }
                } else {
                    progressBar.classList.remove('bg-primary');
                    progressBar.classList.add('bg-danger');
                }
            }
        })
        .catch(error => {
            console.error('Error checking scan status:', error);
            clearInterval(statusCheckInterval);
            showAlert('Error checking scan status', 'danger');
        });
    }
    
    function showAlert(message, type = 'primary') {
        // Create alert element
        const alertEl = document.createElement('div');
        alertEl.className = `alert alert-${type} alert-dismissible fade show`;
        alertEl.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        
        // Find a place to show it
        const container = document.querySelector('main');
        container.insertBefore(alertEl, container.firstChild);
        
        // Auto dismiss after 5 seconds
        setTimeout(() => {
            alertEl.classList.remove('show');
            setTimeout(() => alertEl.remove(), 150);
        }, 5000);
    }
}); 