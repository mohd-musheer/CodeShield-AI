// CodeShield AI Frontend Logic

document.addEventListener("DOMContentLoaded", () => {
    // Elements
    const repoUrlInput = document.getElementById("repoUrlInput");
    const scanBtn = document.getElementById("scanBtn");
    const progressContainer = document.getElementById("progressContainer");
    const progressBarFill = document.getElementById("progressBarFill");
    const progressStatus = document.getElementById("progressStatus");
    const progressMsg = document.getElementById("progressMsg");
    const progressPercent = document.getElementById("progressPercent");
    const welcomeState = document.getElementById("welcomeState");
    const errorAlert = document.getElementById("errorAlert");
    const errorMsgText = document.getElementById("errorMsgText");
    const dashboard = document.getElementById("dashboard");
    
    // Stats Elements
    const scoreValue = document.getElementById("scoreValue");
    const scoreRingFill = document.getElementById("scoreRingFill");
    const scoreLabel = document.getElementById("scoreLabel");
    const scoreSummary = document.getElementById("scoreSummary");
    const statName = document.getElementById("statName");
    const statFiles = document.getElementById("statFiles");
    const statSize = document.getElementById("statSize");
    const statFrameworks = document.getElementById("statFrameworks");
    const statDuration = document.getElementById("statDuration");
    const statConfigs = document.getElementById("statConfigs");
    
    // Download elements
    const exportFormatSelect = document.getElementById("exportFormatSelect");
    const downloadBtn = document.getElementById("downloadBtn");
    
    // Filters & Findings
    const findingSearch = document.getElementById("findingSearch");
    const filterBadges = document.querySelectorAll(".filter-badge");
    const findingsContainer = document.getElementById("findingsContainer");
    
    // Severity Counters
    const countAll = document.getElementById("countAll");
    const countCritical = document.getElementById("countCritical");
    const countHigh = document.getElementById("countHigh");
    const countMedium = document.getElementById("countMedium");
    const countLow = document.getElementById("countLow");

    // Input Tabs Elements
    const tabButtons = document.querySelectorAll(".tab-btn");
    const textInputGroup = document.getElementById("textInputGroup");
    const dragDropGroup = document.getElementById("dragDropGroup");
    const zipFileInput = document.getElementById("zipFileInput");
    const selectedFileName = document.getElementById("selectedFileName");

    // Theme Switcher Elements
    const themeButtons = document.querySelectorAll(".theme-btn");

    // Category Scores Element
    const categoryScoresContainer = document.getElementById("categoryScoresContainer");

    // Code Viewer Modal Elements
    const codeViewerModal = document.getElementById("codeViewerModal");
    const closeCodeModalBtn = document.getElementById("closeCodeModalBtn");
    const codeModalTitle = document.getElementById("codeModalTitle");
    const codeModalSeverity = document.getElementById("codeModalSeverity");
    const codeModalFilePath = document.getElementById("codeModalFilePath");
    const codeModalLineNo = document.getElementById("codeModalLineNo");
    const codeBeforeContent = document.getElementById("codeBeforeContent");
    const codeAfterContent = document.getElementById("codeAfterContent");
    const copyCodeBtn = document.getElementById("copyCodeBtn");
    const copyPatchBtn = document.getElementById("copyPatchBtn");
    const downloadPatchBtn = document.getElementById("downloadPatchBtn");
    const codeTabButtons = document.querySelectorAll(".code-tab-btn");
    const codeBeforePane = document.getElementById("codeBeforePane");
    const codeAfterPane = document.getElementById("codeAfterPane");

    // Advanced Progress Elements
    const progCurrentStage = document.getElementById("progCurrentStage");
    const progFilesScanned = document.getElementById("progFilesScanned");
    const progChunksChecked = document.getElementById("progChunksChecked");
    const progFindingsFound = document.getElementById("progFindingsFound");
    const progElapsedTime = document.getElementById("progElapsedTime");
    const progEstimatedRemaining = document.getElementById("progEstimatedRemaining");
    const cancelScanBtn = document.getElementById("cancelScanBtn");

    // State Variables
    let currentFindings = [];
    let activeSeverityFilter = "all";
    let activeSearchQuery = "";
    let currentScanId = "";
    let currentSocket = null;
    let activePollingInterval = null;
    let activeInputTab = "github"; // github, gitlab, local, zip
    let currentTheme = "system"; // system, dark, light

    // Progress duration timer
    let progressTimer = null;
    let elapsedSeconds = 0;

    // Active expanded finding ID (accordion state)
    let expandedFindingId = null;

    // Temp active viewing finding for the code viewer modal
    let activeViewingFinding = null;

    // Initialize logic
    initApp();

    function initApp() {
        // Theme selection load
        const savedTheme = localStorage.getItem("codeshield_theme");
        if (savedTheme) {
            applyTheme(savedTheme);
        } else {
            applyTheme("system");
        }

        // Setup theme events
        themeButtons.forEach(btn => {
            btn.addEventListener("click", () => {
                const theme = btn.getAttribute("data-theme");
                applyTheme(theme);
            });
        });

        // Setup input source tabs
        tabButtons.forEach(btn => {
            btn.addEventListener("click", () => {
                tabButtons.forEach(b => b.classList.remove("active"));
                btn.classList.add("active");
                switchInputTab(btn.getAttribute("data-tab"));
            });
        });

        // Setup Drag & Drop listeners
        setupDragAndDrop();

        // Register action listeners
        scanBtn.addEventListener("click", triggerScan);
        repoUrlInput.addEventListener("keypress", (e) => {
            if (e.key === "Enter") triggerScan();
        });

        cancelScanBtn.addEventListener("click", triggerCancelScan);

        downloadBtn.addEventListener("click", () => {
            if (currentScanId) {
                const format = exportFormatSelect.value;
                window.location.href = `/repository/report?scan_id=${currentScanId}&format=${format}`;
            }
        });

        // Modal Close Button
        closeCodeModalBtn.addEventListener("click", () => {
            codeViewerModal.classList.add("hidden");
        });

        // Modal Close overlay click
        codeViewerModal.addEventListener("click", (e) => {
            if (e.target === codeViewerModal) {
                codeViewerModal.classList.add("hidden");
            }
        });

        // Code Viewer Tabs
        codeTabButtons.forEach(btn => {
            btn.addEventListener("click", () => {
                codeTabButtons.forEach(b => b.classList.remove("active"));
                btn.classList.add("active");
                const tab = btn.getAttribute("data-code-tab");
                if (tab === "before") {
                    codeBeforePane.classList.remove("hidden");
                    codeAfterPane.classList.add("hidden");
                } else {
                    codeBeforePane.classList.add("hidden");
                    codeAfterPane.classList.remove("hidden");
                }
            });
        });

        // Code Copy handlers
        copyCodeBtn.addEventListener("click", () => {
            if (activeViewingFinding) {
                const content = codeBeforeContent.textContent;
                navigator.clipboard.writeText(content);
                alert("Source code copied to clipboard!");
            }
        });

        copyPatchBtn.addEventListener("click", () => {
            if (activeViewingFinding && activeViewingFinding.patch) {
                navigator.clipboard.writeText(activeViewingFinding.patch);
                alert("Patch diff copied to clipboard!");
            } else {
                alert("No patch diff generated for this finding.");
            }
        });

        downloadPatchBtn.addEventListener("click", () => {
            if (currentScanId && activeViewingFinding) {
                window.location.href = `/repository/report?scan_id=${currentScanId}&format=patch_diff`;
            }
        });

        // Search & filter
        findingSearch.addEventListener("input", (e) => {
            activeSearchQuery = e.target.value.toLowerCase().trim();
            renderFindings();
        });

        filterBadges.forEach(badge => {
            badge.addEventListener("click", () => {
                filterBadges.forEach(b => b.classList.remove("active"));
                badge.classList.add("active");
                activeSeverityFilter = badge.getAttribute("data-severity");
                renderFindings();
            });
        });

        // Recovery check on load/refresh
        checkRecoveryOnLoad();
    }

    // Themes Engine
    function applyTheme(theme) {
        currentTheme = theme;
        localStorage.setItem("codeshield_theme", theme);
        
        themeButtons.forEach(btn => {
            btn.classList.remove("active");
            if (btn.getAttribute("data-theme") === theme) {
                btn.classList.add("active");
            }
        });

        document.body.classList.remove("theme-light", "theme-dark");

        if (theme === "system") {
            const prefersLight = window.matchMedia("(prefers-color-scheme: light)").matches;
            if (prefersLight) {
                document.body.classList.add("theme-light");
            } else {
                document.body.classList.add("theme-dark");
            }
        } else if (theme === "light") {
            document.body.classList.add("theme-light");
        } else {
            document.body.classList.add("theme-dark");
        }
    }

    // Input Tabs Engine
    function switchInputTab(tab) {
        activeInputTab = tab;
        selectedFileName.classList.add("hidden");
        selectedFileName.textContent = "";
        zipFileInput.value = "";

        if (tab === "zip") {
            textInputGroup.classList.add("hidden");
            dragDropGroup.classList.remove("hidden");
        } else {
            textInputGroup.classList.remove("hidden");
            dragDropGroup.classList.add("hidden");

            if (tab === "github") {
                repoUrlInput.placeholder = "Enter public GitHub Repository URL (e.g. https://github.com/fastapi/fastapi)...";
                repoUrlInput.value = "";
            } else if (tab === "gitlab") {
                repoUrlInput.placeholder = "Enter public GitLab Repository URL (e.g. https://gitlab.com/gitlab-org/gitlab)...";
                repoUrlInput.value = "";
            } else if (tab === "local") {
                repoUrlInput.placeholder = "Enter absolute local folder path (e.g. C:/Projects/my-app)...";
                repoUrlInput.value = "";
            }
        }
    }

    // Setup drag and drop for ZIP files
    function setupDragAndDrop() {
        // Clicking browse triggers file input click
        dragDropGroup.addEventListener("click", () => {
            zipFileInput.click();
        });

        zipFileInput.addEventListener("change", (e) => {
            if (e.target.files.length > 0) {
                handleZipFile(e.target.files[0]);
            }
        });

        dragDropGroup.addEventListener("dragover", (e) => {
            e.preventDefault();
            dragDropGroup.classList.add("dragover");
        });

        dragDropGroup.addEventListener("dragleave", () => {
            dragDropGroup.classList.remove("dragover");
        });

        dragDropGroup.addEventListener("drop", (e) => {
            e.preventDefault();
            dragDropGroup.classList.remove("dragover");
            if (e.dataTransfer.files.length > 0) {
                handleZipFile(e.dataTransfer.files[0]);
            }
        });
    }

    async function handleZipFile(file) {
        if (!file.name.endsWith(".zip")) {
            showError("Only ZIP archives are supported.");
            return;
        }

        selectedFileName.textContent = `Selected: ${file.name} (${formatBytes(file.size)})`;
        selectedFileName.classList.remove("hidden");

        // Reset UI states
        errorAlert.classList.add("hidden");
        welcomeState.classList.add("hidden");
        dashboard.classList.add("hidden");
        progressContainer.classList.remove("hidden");
        
        scanBtn.disabled = true;
        startElapsedTimeTimer();
        updateProgress("initializing", 5, "Initializing upload...", "Sending zip file to scanning backend...");

        try {
            const formData = new FormData();
            formData.append("file", file);

            const res = await fetch("/repository/upload", {
                method: "POST",
                body: formData
            });

            if (!res.ok) {
                const errData = await res.json();
                throw new Error(errData.detail || "Failed to upload ZIP archive.");
            }

            const data = await res.json();
            currentScanId = data.scan_id;
            localStorage.setItem("codeshield_last_scan_id", currentScanId);
            connectProgressTracker(currentScanId);

        } catch (err) {
            showError(err.message);
            resetScanButton();
            stopElapsedTimeTimer();
        }
    }

    // Clean tracking pollers and websockets
    function stopAllTracking() {
        if (activePollingInterval) {
            clearInterval(activePollingInterval);
            activePollingInterval = null;
        }
        if (currentSocket) {
            try {
                currentSocket.close();
            } catch(e) {}
            currentSocket = null;
        }
        stopElapsedTimeTimer();
    }

    // Elapsed Timer
    function startElapsedTimeTimer() {
        stopElapsedTimeTimer();
        elapsedSeconds = 0;
        progElapsedTime.textContent = "0s";
        progressTimer = setInterval(() => {
            elapsedSeconds++;
            progElapsedTime.textContent = `${elapsedSeconds}s`;
        }, 1000);
    }

    function stopElapsedTimeTimer() {
        if (progressTimer) {
            clearInterval(progressTimer);
            progressTimer = null;
        }
    }

    // Trigger Scan
    async function triggerScan() {
        const value = repoUrlInput.value.trim();
        if (!value) {
            showError("Please enter a valid URL or folder path.");
            return;
        }

        // Reset UI states
        errorAlert.classList.add("hidden");
        welcomeState.classList.add("hidden");
        dashboard.classList.add("hidden");
        progressContainer.classList.remove("hidden");
        
        scanBtn.disabled = true;
        startElapsedTimeTimer();
        updateProgress("initializing", 5, "Initializing analysis pipeline...", "Sending request to security scanner backend...");

        try {
            let payload = {};
            if (activeInputTab === "local") {
                payload = { local_path: value };
            } else {
                payload = { repository_url: value };
            }

            const response = await fetch("/repository/analyze?sync=false", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                const errData = await response.json();
                throw new Error(errData.detail || "Failed to trigger scan pipeline.");
            }

            const data = await response.json();
            currentScanId = data.scan_id;
            localStorage.setItem("codeshield_last_scan_id", currentScanId);
            connectProgressTracker(currentScanId);

        } catch (err) {
            showError(err.message);
            resetScanButton();
            stopElapsedTimeTimer();
        }
    }

    // Trigger Cancel Scan
    async function triggerCancelScan() {
        if (!currentScanId) return;
        
        updateProgress("cancelled", 100, "Cancelling scan...", "Sending cancellation signal to backend...");
        try {
            await fetch(`/repository/cancel/${currentScanId}`, { method: "POST" });
        } catch (e) {
            console.warn("Failed to notify scan cancellation: ", e);
        }
        
        stopAllTracking();
        localStorage.removeItem("codeshield_last_scan_id");
        welcomeState.classList.remove("hidden");
        progressContainer.classList.add("hidden");
        resetScanButton();
    }

    // WebSocket / Polling Tracker
    function connectProgressTracker(scanId) {
        const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        const wsUrl = `${protocol}//${window.location.host}/ws/scan/${scanId}`;
        
        try {
            const ws = new WebSocket(wsUrl);
            currentSocket = ws;

            ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                if (data.error) {
                    showError(`Scanner WebSocket Error: ${data.error}`);
                    resetScanButton();
                    ws.close();
                    return;
                }

                updateProgress(data.status, data.percent, getProgressTitle(data.status), data.message, data.stages);

                if (data.status === "completed" || data.percent === 100) {
                    stopAllTracking();
                    fetchScanResults(scanId);
                } else if (data.status === "failed") {
                    showError("Scan pipeline failed. Ensure parameters are correct.");
                    resetScanButton();
                    stopAllTracking();
                } else if (data.status === "cancelled") {
                    stopAllTracking();
                    localStorage.removeItem("codeshield_last_scan_id");
                    welcomeState.classList.remove("hidden");
                    progressContainer.classList.add("hidden");
                    resetScanButton();
                }
            };

            ws.onerror = () => {
                runProgressPolling(scanId);
            };

            ws.onclose = () => {
                if (currentScanId === scanId) {
                    runProgressPolling(scanId);
                }
            };

        } catch (e) {
            runProgressPolling(scanId);
        }
    }

    // Fallback polling mechanism
    function runProgressPolling(scanId) {
        if (activePollingInterval) {
            clearInterval(activePollingInterval);
        }

        activePollingInterval = setInterval(async () => {
            try {
                const res = await fetch(`/scan/status/${scanId}`);
                if (!res.ok) throw new Error("Progress polling failed");
                const data = await res.json();
                
                updateProgress(data.status, data.percent, getProgressTitle(data.status), data.message, data.stages);

                if (data.status === "completed" || data.percent === 100) {
                    stopAllTracking();
                    fetchScanResults(scanId);
                } else if (data.status === "failed") {
                    stopAllTracking();
                    showError("Scan pipeline failed in background.");
                    resetScanButton();
                } else if (data.status === "cancelled") {
                    stopAllTracking();
                    localStorage.removeItem("codeshield_last_scan_id");
                    welcomeState.classList.remove("hidden");
                    progressContainer.classList.add("hidden");
                    resetScanButton();
                }
            } catch (e) {
                console.warn("Polling connection error: ", e);
            }
        }, 1500);
    }

    // Fetch findings results
    async function fetchScanResults(scanId) {
        updateProgress("rendering", 98, "Retrieving findings...", "Building interactive dashboard panels...");
        try {
            const response = await fetch(`/repository/report?scan_id=${scanId}&format=json`);
            if (!response.ok) {
                throw new Error("Failed to load completed report results.");
            }

            const report = await response.json();
            currentFindings = report.findings;
            
            // Populate metrics & stats
            populateDashboard(report);
            
            // Hide progress and display dashboard
            progressContainer.classList.add("hidden");
            dashboard.classList.remove("hidden");
            resetScanButton();

        } catch (err) {
            showError(err.message);
            resetScanButton();
        }
    }

    // Map stages status to counts
    function updateProgress(status, percent, title, message, stages = {}) {
        progressBarFill.style.width = `${percent}%`;
        progressPercent.textContent = percent;
        progressStatus.textContent = title;
        progressMsg.textContent = message;

        progCurrentStage.textContent = status.toUpperCase().replace("_", " ");

        // Simple mock calculations for files and findings count during progress
        if (stages) {
            let filesScanned = 0;
            let chunksChecked = 0;
            let findingsFound = 0;

            if (stages.repository_analysis === "completed") filesScanned = 10;
            if (stages.smart_chunking === "completed") chunksChecked = 24;
            if (stages.static_scan === "completed") {
                filesScanned = 15;
                findingsFound = 2;
            }
            if (stages.ai_security_review === "completed") {
                chunksChecked = 36;
                findingsFound = 5;
            }

            progFilesScanned.textContent = filesScanned || "-";
            progChunksChecked.textContent = chunksChecked || "-";
            progFindingsFound.textContent = findingsFound || "-";
        }

        // Estimate remaining time
        if (percent > 0 && percent < 100) {
            const totalEst = Math.round((elapsedSeconds / percent) * 100);
            const remaining = Math.max(1, totalEst - elapsedSeconds);
            progEstimatedRemaining.textContent = `~${remaining}s`;
        } else {
            progEstimatedRemaining.textContent = "-";
        }
    }

    function getProgressTitle(status) {
        const titles = {
            "queued": "Scan queued, waiting for pipeline...",
            "initializing": "Initializing scan...",
            "cloning": "Cloning repository...",
            "loading": "Parsing repository files...",
            "analyzing": "Analyzing language & project context...",
            "chunking": "Constructing codebase chunks...",
            "static_scan": "Running static scanning checks...",
            "ai_scan": "Running Groq AI semantic review...",
            "reasoning": "Performing cross-file analysis...",
            "scoring": "Calculating security posture score...",
            "generating_report": "Generating reports...",
            "completed": "Scan completed!"
        };
        return titles[status] || "Scanning repository...";
    }

    // Populate Dashboard Data
    function populateDashboard(report) {
        // Score
        const score = report.score.overall_score;
        scoreValue.textContent = score;
        
        // Circular gauge dashoffset
        const circumference = 314.16;
        const offset = circumference * (1 - score / 100);
        scoreRingFill.style.strokeDashoffset = offset;
        
        // Color classification of score ring
        let ringColor = "#22c55e"; // green
        let riskLabel = "Secure";
        
        if (score < 40) {
            ringColor = "#ef4444"; // red
            riskLabel = "Critical Risk";
        } else if (score < 70) {
            ringColor = "#f97316"; // orange
            riskLabel = "High Risk";
        } else if (score < 90) {
            ringColor = "#eab308"; // yellow
            riskLabel = "Moderate Risk";
        }
        
        scoreRingFill.style.stroke = ringColor;
        scoreLabel.textContent = riskLabel;
        scoreLabel.style.color = ringColor;
        scoreSummary.textContent = report.score.risk_summary;

        // Repository general statistics
        statName.textContent = report.repository_name;
        statFiles.textContent = report.metadata.total_files;
        statSize.textContent = formatBytes(report.metadata.total_size);
        
        // Framework list
        statFrameworks.textContent = report.metadata.frameworks.join(", ") || "None Detected";
        
        // Scan Duration
        statDuration.textContent = `${report.metadata.scan_duration_sec || 0}s`;

        // Configurations
        statConfigs.textContent = report.metadata.configs.map(c => c.split(" ")[0]).join(", ") || "None Detected";

        // Count severity values
        const breakdown = report.score.severity_breakdown;
        countAll.textContent = report.findings.length;
        countCritical.textContent = breakdown.CRITICAL || 0;
        countHigh.textContent = breakdown.HIGH || 0;
        countMedium.textContent = breakdown.MEDIUM || 0;
        countLow.textContent = breakdown.LOW || 0;

        // Populate Category Health scores
        populateCategoryScores(report.score.category_scores);

        // Reset filter
        activeSeverityFilter = "all";
        filterBadges.forEach(b => {
            b.classList.remove("active");
            if (b.getAttribute("data-severity") === "all") b.classList.add("active");
        });

        // Reset accordion expanded ID
        expandedFindingId = null;

        renderFindings();
    }

    function populateCategoryScores(categoryScores = {}) {
        categoryScoresContainer.innerHTML = "";
        
        // List of core high-level categories
        const categoriesList = [
            "Authentication",
            "Secrets",
            "Dependencies",
            "Configuration",
            "Docker",
            "Input Validation",
            "Logging",
            "Cryptography"
        ];

        categoriesList.forEach(cat => {
            const scoreVal = categoryScores[cat] !== undefined ? categoryScores[cat] : 100;
            
            const scoreItem = document.createElement("div");
            scoreItem.className = "score-item";
            
            scoreItem.innerHTML = `
                <div class="score-item-lbl-row">
                    <span>${cat}</span>
                    <span style="color: ${scoreVal < 70 ? 'var(--critical)' : scoreVal < 90 ? 'var(--medium)' : 'var(--low)'}">${scoreVal}/100</span>
                </div>
                <div class="score-item-bar-bg">
                    <div class="score-item-bar-fill" style="width: ${scoreVal}%"></div>
                </div>
            `;
            
            categoryScoresContainer.appendChild(scoreItem);
        });
    }

    // Filters and renders findings cards accordion
    function renderFindings() {
        findingsContainer.innerHTML = "";
        
        // Filter findings
        const filtered = currentFindings.filter(f => {
            const matchesSev = activeSeverityFilter === "all" || f.severity.toLowerCase() === activeSeverityFilter;
            const matchesSearch = !activeSearchQuery || 
                f.title.toLowerCase().includes(activeSearchQuery) || 
                f.file_path.toLowerCase().includes(activeSearchQuery) ||
                (f.cwe && f.cwe.toLowerCase().includes(activeSearchQuery)) ||
                (f.owasp && f.owasp.toLowerCase().includes(activeSearchQuery)) ||
                f.category.toLowerCase().includes(activeSearchQuery);
            return matchesSev && matchesSearch;
        });

        if (filtered.length === 0) {
            findingsContainer.innerHTML = `
                <div class="welcome-section glass" style="padding: 40px; margin-top: 0;">
                    <h3>No matching findings</h3>
                    <p>Try clearing filters or search keyword to view other issues.</p>
                </div>
            `;
            return;
        }

        filtered.forEach(f => {
            const item = document.createElement("div");
            item.className = "finding-item glass";
            
            const sevLower = f.severity.toLowerCase();
            const isExpanded = expandedFindingId === f.finding_id;

            item.innerHTML = `
                <div class="finding-item-lbl-row">
                    <div class="severity-indicator sev-${sevLower}"></div>
                    <div class="finding-content" style="flex: 1; margin-left: 15px;">
                        <div class="finding-header">
                            <h4 style="color: #ffffff; font-weight: 600; margin-bottom: 2px;">${escapeHtml(f.title)}</h4>
                            <span class="badge ${sevLower}">${f.severity}</span>
                        </div>
                        <p class="finding-item-desc" style="font-size: 0.9em; margin-bottom: 4px;">${escapeHtml(f.description)}</p>
                        <div class="finding-meta" style="font-size: 0.8em; color: var(--text-muted);">
                            <strong>Category:</strong> <code>${f.category}</code> | 
                            <strong>File:</strong> <code>${f.file_path}</code> ${f.line_number ? `line ${f.line_number}` : ''}
                        </div>
                    </div>
                    <div class="accordion-arrow" style="color: var(--text-muted); font-size: 1.2em; padding: 0 10px;">
                        ${isExpanded ? '&#9650;' : '&#9660;'}
                    </div>
                </div>
                ${isExpanded ? `
                    <div class="finding-details-expanded">
                        <div class="finding-meta-tags">
                            ${f.cwe ? `<span class="tag-badge cwe">${escapeHtml(f.cwe)}</span>` : ''}
                            ${f.owasp ? `<span class="tag-badge owasp">${escapeHtml(f.owasp)}</span>` : ''}
                            <span class="tag-badge">Confidence: ${f.confidence}</span>
                        </div>
                        
                        <div class="exp-detail-block">
                            <h5 style="color: #ffffff; margin-bottom: 4px; font-size: 0.9em; text-transform: uppercase; letter-spacing: 0.5px;">Security Explanation</h5>
                            <p style="font-size: 0.9em; color: var(--text-muted); line-height: 1.6;">${escapeHtml(f.explanation)}</p>
                        </div>
                        
                        ${f.attack_scenario ? `
                            <div class="exp-detail-block">
                                <h5 style="color: #ffffff; margin-bottom: 4px; font-size: 0.9em; text-transform: uppercase; letter-spacing: 0.5px;">Attack / Exploit Scenario</h5>
                                <p style="font-size: 0.9em; color: var(--text-muted); line-height: 1.6;">${escapeHtml(f.attack_scenario)}</p>
                            </div>
                        ` : ''}

                        ${f.business_impact ? `
                            <div class="exp-detail-block">
                                <h5 style="color: #ffffff; margin-bottom: 4px; font-size: 0.9em; text-transform: uppercase; letter-spacing: 0.5px;">Business Impact</h5>
                                <p style="font-size: 0.9em; color: var(--text-muted); line-height: 1.6;">${escapeHtml(f.business_impact)}</p>
                            </div>
                        ` : ''}

                        <div class="exp-detail-block">
                            <h5 style="color: #ffffff; margin-bottom: 4px; font-size: 0.9em; text-transform: uppercase; letter-spacing: 0.5px;">Remediation Suggestion</h5>
                            <p style="font-size: 0.9em; color: var(--text-muted); line-height: 1.6; margin-bottom: 12px;">${escapeHtml(f.fix_suggestion)}</p>
                            
                            <div style="display: flex; gap: 10px;">
                                <button class="primary-btn view-code-trigger-btn" style="padding: 8px 16px; font-size: 0.85em;">
                                    <span>View & Highlight Code</span>
                                </button>
                                ${f.patch ? `
                                    <button class="sec-btn copy-patch-trigger-btn" style="padding: 8px 16px; font-size: 0.85em; flex: 0 0 auto;">
                                        <span>Copy Fix Patch</span>
                                    </button>
                                ` : ''}
                            </div>
                        </div>

                        ${f.references && f.references.length > 0 ? `
                            <div class="exp-detail-block" style="border-top: 1px solid var(--border-color); padding-top: 12px; margin-top: 5px;">
                                <h5 style="color: #ffffff; margin-bottom: 6px; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.5px;">References</h5>
                                <ul style="list-style-type: none; padding-left: 0; font-size: 0.85em;">
                                    ${f.references.map(ref => `
                                        <li style="margin-bottom: 4px;"><a href="${ref}" target="_blank" style="color: var(--primary); text-decoration: none;">&rarr; ${escapeHtml(ref)}</a></li>
                                    `).join('')}
                                </ul>
                            </div>
                        ` : ''}
                    </div>
                ` : ''}
            `;

            // Accordion toggle click (clicking non-buttons toggles accordion)
            item.addEventListener("click", (e) => {
                if (e.target.closest("button") || e.target.closest("a")) return;
                expandedFindingId = isExpanded ? null : f.finding_id;
                renderFindings();
            });

            // "View & Highlight Code" trigger inside expanded finding
            if (isExpanded) {
                const viewBtn = item.querySelector(".view-code-trigger-btn");
                if (viewBtn) {
                    viewBtn.addEventListener("click", () => {
                        openCodeViewerModal(f);
                    });
                }

                const copyPatchBtn = item.querySelector(".copy-patch-trigger-btn");
                if (copyPatchBtn) {
                    copyPatchBtn.addEventListener("click", () => {
                        navigator.clipboard.writeText(f.patch);
                        alert("Unified diff patch copied to clipboard!");
                    });
                }
            }

            findingsContainer.appendChild(item);
        });
    }

    // Interactive Code Viewer Modal open & lines highlighting
    async function openCodeViewerModal(finding) {
        activeViewingFinding = finding;
        
        codeModalTitle.textContent = finding.title;
        codeModalSeverity.textContent = finding.severity;
        codeModalSeverity.className = `badge ${finding.severity.toLowerCase()}`;
        codeModalFilePath.textContent = finding.file_path;
        codeModalLineNo.textContent = finding.line_number ? `Line ${finding.line_number}` : "Line -";

        // Reset tab to Vulnerable code
        codeTabButtons.forEach(b => {
            b.classList.remove("active");
            if (b.getAttribute("data-code-tab") === "before") b.classList.add("active");
        });
        codeBeforePane.classList.remove("hidden");
        codeAfterPane.classList.add("hidden");

        codeBeforeContent.innerHTML = "Loading source file contents...";
        codeAfterContent.innerHTML = "";

        // Show modal early
        codeViewerModal.classList.remove("hidden");

        try {
            // Load file content from backend cache
            const response = await fetch(`/repository/file?scan_id=${currentScanId}&file_path=${encodeURIComponent(finding.file_path)}`);
            if (!response.ok) {
                throw new Error("Could not retrieve source file from backend.");
            }

            const data = await response.json();
            const sourceCode = data.content || "";
            
            // Render line numbered items
            renderLineNumberedCode(codeBeforeContent, sourceCode, finding.line_number);

            // Remediated code render (from fix_suggestion / suggested code or patch diff application mockup)
            let remediatedCode = "";
            if (finding.patch) {
                // Apply mock patch overlay or just display the suggested code segment
                remediatedCode = `${finding.fix_suggestion}\n\n# --- Patch Diff Guidelines ---\n${finding.patch}`;
            } else {
                remediatedCode = finding.fix_suggestion;
            }
            renderLineNumberedCode(codeAfterContent, remediatedCode, null);

        } catch (e) {
            codeBeforeContent.textContent = `Source preview unavailable.\n\nReason: ${e.message}\n\nOriginal Snippet:\n${finding.code_snippet || "N/A"}`;
            codeAfterContent.textContent = finding.fix_suggestion;
        }
    }

    function renderLineNumberedCode(container, codeText, highlightLine) {
        container.innerHTML = "";
        
        const lines = codeText.split("\n");
        const codeLinesDiv = document.createElement("div");
        codeLinesDiv.className = "code-lines";

        lines.forEach((lineText, idx) => {
            const lineNo = idx + 1;
            const lineItem = document.createElement("div");
            lineItem.className = "code-line-item";
            
            if (highlightLine && lineNo === parseInt(highlightLine)) {
                lineItem.classList.add("highlighted-line");
            }

            lineItem.innerHTML = `
                <div class="line-no-col">${lineNo}</div>
                <div class="line-code-col">${escapeHtml(lineText || " ")}</div>
            `;
            
            codeLinesDiv.appendChild(lineItem);
        });

        container.appendChild(codeLinesDiv);
    }

    // Helper functions
    function showError(msg) {
        errorMsgText.textContent = msg;
        errorAlert.classList.remove("hidden");
        progressContainer.classList.add("hidden");
    }

    function resetScanButton() {
        scanBtn.disabled = false;
    }

    function formatBytes(bytes, decimals = 2) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }

    function escapeHtml(text) {
        if (!text) return "";
        return text
            .toString()
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // Recovery check on load/refresh
    async function checkRecoveryOnLoad() {
        const lastScanId = localStorage.getItem("codeshield_last_scan_id");
        if (!lastScanId) return;

        try {
            const res = await fetch(`/scan/status/${lastScanId}`);
            if (!res.ok) return;
            const data = await res.json();

            if (data.status === "completed") {
                currentScanId = lastScanId;
                welcomeState.classList.add("hidden");
                progressContainer.classList.add("hidden");
                fetchScanResults(lastScanId);
            } else if (data.status === "failed" || data.status === "cancelled") {
                localStorage.removeItem("codeshield_last_scan_id");
            } else if (data.status !== "unknown") {
                currentScanId = lastScanId;
                welcomeState.classList.add("hidden");
                progressContainer.classList.remove("hidden");
                scanBtn.disabled = true;
                
                // Resume timer
                startElapsedTimeTimer();

                updateProgress(data.status, data.percent, getProgressTitle(data.status), data.message, data.stages);
                connectProgressTracker(lastScanId);
            }
        } catch (e) {
            console.warn("Failed to check recovery on load: ", e);
        }
    }
});
