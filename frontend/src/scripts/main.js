document.addEventListener('DOMContentLoaded', function() {
    // API endpoint from config.js
    // Make sure API_ENDPOINT is defined in config.js
    if (typeof API_ENDPOINT === 'undefined') {
        console.error('API_ENDPOINT is not defined in config.js');
        API_ENDPOINT = '';
    }
    
    // DOM Elements
    const themeToggleBtn = document.getElementById('theme-toggle-btn');
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabPanes = document.querySelectorAll('.tab-pane');
    const uploadArea = document.getElementById('upload-area');
    const fileInput = document.getElementById('file-input');
    const fileSelectBtn = document.getElementById('file-select-btn');
    const fileName = document.getElementById('file-name');
    const analyzeFileBtn = document.getElementById('analyze-file-btn');
    const urlInput = document.getElementById('url-input');
    const analyzeUrlBtn = document.getElementById('analyze-url-btn');
    const loadingOverlay = document.getElementById('loading-overlay');
    const resultsPlaceholder = document.getElementById('results-placeholder');
    const resultsContent = document.getElementById('results-content');
    const analysisTypeIcon = document.getElementById('analysis-type-icon');
    const analysisTypeText = document.getElementById('analysis-type-text');
    const resultsTimestamp = document.getElementById('results-timestamp').querySelector('span');
    const riskLevel = document.getElementById('risk-level');
    const infoTitle = document.getElementById('info-title');
    const infoDetails = document.getElementById('info-details');
    const detailedResults = document.getElementById('detailed-results');
    const rawJson = document.getElementById('raw-json');
    const accordionHeaders = document.querySelectorAll('.accordion-header');
    
    // Theme Toggle
    themeToggleBtn.addEventListener('click', function() {
        const currentTheme = document.body.getAttribute('data-theme') || 'light';
        const newTheme = currentTheme === 'light' ? 'dark' : 'light';
        document.body.setAttribute('data-theme', newTheme);
        
        // Update icon
        const icon = themeToggleBtn.querySelector('i');
        if (newTheme === 'dark') {
            icon.classList.remove('fa-moon');
            icon.classList.add('fa-sun');
        } else {
            icon.classList.remove('fa-sun');
            icon.classList.add('fa-moon');
        }
        
        // Save preference
        localStorage.setItem('theme', newTheme);
    });
    
    // Load saved theme preference
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
        document.body.setAttribute('data-theme', savedTheme);
        if (savedTheme === 'dark') {
            const icon = themeToggleBtn.querySelector('i');
            icon.classList.remove('fa-moon');
            icon.classList.add('fa-sun');
        }
    }
    
    // Tab Switching
    tabBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const tabId = this.dataset.tab;
            
            // Update active tab button
            tabBtns.forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');
            
            // Show active tab pane
            tabPanes.forEach(pane => pane.classList.remove('active'));
            document.getElementById(`${tabId}-tab`).classList.add('active');
        });
    });
    
    // File Upload Handling
    fileSelectBtn.addEventListener('click', function() {
        fileInput.click();
    });
    
    fileInput.addEventListener('change', function() {
        if (this.files.length > 0) {
            const file = this.files[0];
            fileName.textContent = file.name;
            analyzeFileBtn.disabled = false;
        }
    });
    
    // Drag and Drop
    uploadArea.addEventListener('dragover', function(e) {
        e.preventDefault();
        this.classList.add('dragover');
    });
    
    uploadArea.addEventListener('dragleave', function() {
        this.classList.remove('dragover');
    });
    
    uploadArea.addEventListener('drop', function(e) {
        e.preventDefault();
        this.classList.remove('dragover');
        
        if (e.dataTransfer.files.length > 0) {
            const file = e.dataTransfer.files[0];
            fileInput.files = e.dataTransfer.files;
            fileName.textContent = file.name;
            analyzeFileBtn.disabled = false;
        }
    });
    
    // File Analysis
    analyzeFileBtn.addEventListener('click', function() {
        if (fileInput.files.length === 0) return;
        
        const file = fileInput.files[0];
        showLoading();
        
        // Send file to API
        console.log(`Sending file to ${API_ENDPOINT}/analyze/file`);
        fetch(`${API_ENDPOINT}/analyze/file`, {
            method: 'POST',
            body: file,
            headers: {
                'Content-Type': file.type || 'application/octet-stream'
            },
            mode: 'cors' // Explicitly request CORS mode
        })
        .then(response => {
            console.log('File analysis response status:', response.status);
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            displayResults('file', data);
        })
        .catch(error => {
            console.error('Error:', error);
            // Remove the alert to prevent error popup
            displayResults('file', {
                "analysis_type": "file",
                "timestamp": new Date().toISOString(),
                "file_info": {
                    "size": fileInput.files[0].size,
                    "content_type": fileInput.files[0].type || 'application/octet-stream',
                    "hashes": {
                        "md5": "Processing...",
                        "sha1": "Processing...",
                        "sha256": "Processing..."
                    }
                },
                "risk_assessment": {
                    "score": 0,
                    "findings": ["Analysis could not be completed. The service may be unavailable."]
                }
            });
        })
        .finally(() => {
            hideLoading();
        });
    });
    
    // URL Analysis
    analyzeUrlBtn.addEventListener('click', function() {
        const url = urlInput.value.trim();
        
        if (!url) {
            alert('Please enter a URL to analyze.');
            return;
        }
        
        if (!isValidUrl(url)) {
            alert('Please enter a valid URL (e.g., https://example.com).');
            return;
        }
        
        showLoading();
        
        // Send URL to API
        console.log(`Sending URL to ${API_ENDPOINT}/analyze/url`);
        fetch(`${API_ENDPOINT}/analyze/url`, {
            method: 'POST',
            body: JSON.stringify({ url: url }),
            headers: {
                'Content-Type': 'application/json'
            },
            mode: 'cors' // Explicitly request CORS mode
        })
        .then(response => {
            console.log('URL analysis response status:', response.status);
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            displayResults('url', data);
        })
        .catch(error => {
            console.error('Error:', error);
            // Remove the alert to prevent error popup
            displayResults('url', {
                "analysis_type": "url",
                "timestamp": new Date().toISOString(),
                "url": urlInput.value.trim(),
                "url_info": {
                    "domain": new URL(urlInput.value.trim()).hostname,
                    "path": new URL(urlInput.value.trim()).pathname,
                    "query": new URL(urlInput.value.trim()).search,
                    "scheme": new URL(urlInput.value.trim()).protocol.replace(':', '')
                },
                "risk_assessment": {
                    "score": 0,
                    "findings": ["Analysis could not be completed. The service may be unavailable."]
                }
            });
        })
        .finally(() => {
            hideLoading();
        });
    });
    
    // Accordion functionality
    accordionHeaders.forEach(header => {
        header.addEventListener('click', function() {
            this.classList.toggle('active');
            const content = this.nextElementSibling;
            content.classList.toggle('active');
        });
    });
    
    // Helper Functions
    function showLoading() {
        loadingOverlay.classList.add('active');
    }
    
    function hideLoading() {
        loadingOverlay.classList.remove('active');
    }
    
    function isValidUrl(string) {
        try {
            new URL(string);
            return true;
        } catch (_) {
            return false;
        }
    }
    
    function displayResults(type, data) {
        // Hide placeholder, show results
        resultsPlaceholder.style.display = 'none';
        resultsContent.hidden = false;
        
        // Update results type
        if (type === 'file') {
            analysisTypeIcon.innerHTML = '<i class="fas fa-file"></i>';
            analysisTypeText.textContent = 'File Analysis';
            infoTitle.textContent = 'File Info';
            
            // File-specific info
            if (data.file_info) {
                const fileInfo = data.file_info;
                infoDetails.textContent = `${formatBytes(fileInfo.size)} • ${fileInfo.content_type}`;
            }
        } else {
            analysisTypeIcon.innerHTML = '<i class="fas fa-link"></i>';
            analysisTypeText.textContent = 'URL Analysis';
            infoTitle.textContent = 'URL Info';
            
            // URL-specific info
            if (data.url_info) {
                infoDetails.textContent = data.url_info.domain;
            } else {
                infoDetails.textContent = data.url || 'URL analyzed';
            }
        }
        
        // Update timestamp
        resultsTimestamp.textContent = 'Just now';
        
        // Update risk assessment
        if (data.risk_assessment) {
            const riskScore = data.risk_assessment.score;
            let riskText = 'Safe';
            let riskClass = 'safe';
            
            if (riskScore > 70) {
                riskText = 'High Risk';
                riskClass = 'danger';
            } else if (riskScore > 30) {
                riskText = 'Medium Risk';
                riskClass = 'warning';
            } else if (riskScore > 0) {
                riskText = 'Low Risk';
                riskClass = 'safe';
            }
            
            riskLevel.textContent = riskText;
            
            // Update icon class
            const summaryIcon = document.querySelector('.summary-icon');
            summaryIcon.className = 'summary-icon';
            summaryIcon.classList.add(riskClass);
        }
        
        // Format and display detailed results
        let detailedText = '';
        
        if (type === 'file') {
            if (data.file_info && data.file_info.hashes) {
                detailedText += 'File Hashes:\n';
                detailedText += `MD5: ${data.file_info.hashes.md5}\n`;
                detailedText += `SHA1: ${data.file_info.hashes.sha1}\n`;
                detailedText += `SHA256: ${data.file_info.hashes.sha256}\n\n`;
            }
        } else if (type === 'url') {
            if (data.http_info) {
                detailedText += `Status Code: ${data.http_info.status_code}\n\n`;
                detailedText += 'HTTP Headers:\n';
                
                for (const [key, value] of Object.entries(data.http_info.headers)) {
                    detailedText += `${key}: ${value}\n`;
                }
                
                detailedText += '\n';
            }
        }
        
        if (data.risk_assessment && data.risk_assessment.findings) {
            detailedText += 'Findings:\n';
            
            if (data.risk_assessment.findings.length === 0) {
                detailedText += 'No security issues found.\n';
            } else {
                data.risk_assessment.findings.forEach((finding, index) => {
                    detailedText += `${index + 1}. ${finding}\n`;
                });
            }
        }
        
        detailedResults.textContent = detailedText;
        
        // Display raw JSON
        rawJson.textContent = JSON.stringify(data, null, 2);
        
        // Scroll to results
        document.getElementById('results-section').scrollIntoView({ behavior: 'smooth' });
    }
    
    function formatBytes(bytes, decimals = 2) {
        if (bytes === 0) return '0 Bytes';
        
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
        
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }
    
    // Demo Mode - For development/preview only
    // Remove this in production
    const isDemoMode = false;
    
    if (isDemoMode) {
        // Add event listener to the analyze buttons for demo mode
        analyzeFileBtn.addEventListener('click', function(e) {
            // Prevent the actual API call in demo mode
            e.stopImmediatePropagation();
            
            showLoading();
            
            // Simulate API delay
            setTimeout(() => {
                const demoFileData = {
                    "analysis_type": "file",
                    "timestamp": new Date().toISOString(),
                    "file_info": {
                        "size": 1024 * 1024 * 2.5, // 2.5 MB
                        "content_type": "application/pdf",
                        "hashes": {
                            "md5": "d41d8cd98f00b204e9800998ecf8427e",
                            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                        }
                    },
                    "risk_assessment": {
                        "score": 0,
                        "findings": []
                    }
                };
                
                displayResults('file', demoFileData);
                hideLoading();
            }, 1500);
        });
        
        analyzeUrlBtn.addEventListener('click', function(e) {
            // Prevent the actual API call in demo mode
            e.stopImmediatePropagation();
            
            const url = urlInput.value.trim();
            
            if (!url) {
                alert('Please enter a URL to analyze.');
                return;
            }
            
            if (!isValidUrl(url)) {
                alert('Please enter a valid URL (e.g., https://example.com).');
                return;
            }
            
            showLoading();
            
            // Simulate API delay
            setTimeout(() => {
                const demoUrlData = {
                    "analysis_type": "url",
                    "timestamp": new Date().toISOString(),
                    "url": url,
                    "url_info": {
                        "domain": new URL(url).hostname,
                        "path": new URL(url).pathname,
                        "query": new URL(url).search,
                        "scheme": new URL(url).protocol.replace(':', '')
                    },
                    "http_info": {
                        "status_code": 200,
                        "headers": {
                            "Content-Type": "text/html",
                            "Server": "nginx/1.18.0",
                            "X-Powered-By": "PHP/7.4.3",
                            "Cache-Control": "max-age=3600"
                        }
                    },
                    "risk_assessment": {
                        "score": 0,
                        "findings": []
                    }
                };
                
                displayResults('url', demoUrlData);
                hideLoading();
            }, 1500);
        });
    }
});
