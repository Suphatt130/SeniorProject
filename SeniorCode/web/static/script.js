let lineChart30s, barChartRules;
let previousTotalLogs = null; 
const MAX_LINE_POINTS = 20; 

let currentLogs = []; 
let sortState = { column: 'time', asc: false }

function setMaxDate() {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    const hours = String(now.getHours()).padStart(2, '0');
    const minutes = String(now.getMinutes()).padStart(2, '0');
    
    const currentDateTime = `${year}-${month}-${day}T${hours}:${minutes}`;
    
    document.getElementById('start-time').setAttribute('max', currentDateTime);
    document.getElementById('end-time').setAttribute('max', currentDateTime);
}

// --- 1. INITIALIZE FUNCTIONS ON PAGE LOAD ---
document.addEventListener('DOMContentLoaded', () => {
    setMaxDate();
    const savedTheme = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-bs-theme', savedTheme);
    updateThemeIcon(savedTheme);

    initDateDisplay();
    initCharts();
    fetchData();
    setInterval(fetchData, 30000); 
});

// --- DATE DISPLAY FUNCTION ---
function initDateDisplay() {
    const dateElement = document.getElementById('current-date');
    const now = new Date();
    const options = { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' };
    dateElement.textContent = now.toLocaleDateString('en-US', options);
}

// --- CHART INITIALIZATION FUNCTION ---
function initCharts() {
    // --- A. Line Chart (Last 30s Logs) ---
    const ctxLine = document.getElementById('lineChart30s').getContext('2d');
    lineChart30s = new Chart(ctxLine, {
        type: 'line',
        data: {
            labels: [], 
            datasets: [{
                label: 'New Logs (Last 30s)',
                data: [], 
                borderColor: '#0d6efd', 
                backgroundColor: 'rgba(13, 110, 253, 0.1)',
                tension: 0.3,
                fill: true,
                pointRadius: 3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { 
                legend: { display: false }
            },
            scales: {
                x: { display: false },
                y: {
                    beginAtZero: true,
                    grid: { color: '#2c3035' },
                    ticks: { color: '#adb5bd', precision: 0 }
                }
            }
        }
    });

    // --- B. Bar Chart (Rules Detections) ---
    const ctxBar = document.getElementById('barChartRules').getContext('2d');
    barChartRules = new Chart(ctxBar, {
        type: 'bar',
        data: {
            labels: ['Phishing', 'DoS', 'Cryptojacking', 'Brute Force'],
            datasets: [{
                label: 'Total Detections',
                data: [0, 0, 0, 0],
                backgroundColor: [
                    'rgba(220, 53, 69, 0.7)',  // Danger Red (Phishing)
                    'rgba(255, 193, 7, 0.7)',  // Warning Yellow (DoS)
                    'rgba(13, 202, 240, 0.7)', // Info Cyan (Crypto)
                    'rgba(102, 16, 242, 0.7)'  // Primary Purple (Brute Force)
                ],
                borderColor: [
                    '#dc3545', '#ffc107', '#0dcaf0', '#6610f2'
                ],
                borderWidth: 1,
                borderRadius: 5
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { 
                legend: { display: false } 
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: '#2c3035' },
                    ticks: { color: '#adb5bd', precision: 0 }
                },
                x: {
                    grid: { display: false },
                    ticks: { color: '#adb5bd' }
                }
            }
        }
    });
}

function resetFilter() {
    document.getElementById('start-time').value = '';
    document.getElementById('end-time').value = '';
    fetchData();
}

async function fetchData() {
    const badge = document.getElementById('last-update-badge');
    const startInput = document.getElementById('start-time');
    const endInput = document.getElementById('end-time');
    
    const start = startInput.value;
    const end = endInput.value;

    if (start && end) {
        const startDate = new Date(start);
        const endDate = new Date(end);
        const now = new Date();

        if (startDate > endDate) {
            alert("Error: Start time cannot be after end time (e.g., 20/02 to 18/02).");
            return;
        }
        if (endDate > now) {
            alert("Error: You cannot select a time in the future.");
            return;
        }
    }

    let queryParams = "";
    if (start && end) {
        queryParams = `?start=${encodeURIComponent(start)}&end=${encodeURIComponent(end)}`;
    }

    if(badge) badge.textContent = 'Updating...';

    try {
        const [statsRes, logsRes] = await Promise.all([
            fetch(`/api/stats${queryParams}`),
            fetch(`/api/logs${queryParams}`)
        ]);

        const statsData = await statsRes.json();
        const logsData = await logsRes.json();
        
        updateBarChart(statsData);
        currentLogs = logsData;
        applySort();

        if(badge) {
            badge.textContent = (start && end) ? 'Filtered View' : 'Live';
            badge.classList.replace('bg-secondary', 'bg-primary');
        }
        updateTopCards(statsData);

    } catch (err) {
        console.error("Fetch Error:", err);
        if(badge) badge.textContent = 'Error';
    }
}

function updateTopCards(data) {
    // Endpoints
    document.getElementById('endpoints-online').textContent = data.endpoints_online || '-';
    document.getElementById('endpoints-total').textContent = data.endpoints_total || '-';
    // Total Alerts
    document.getElementById('total-alerts').textContent = data.total || 0;
}

function updateLineChart(LogCount) {
    const count = LogCount !== undefined ? LogCount : 0;

    const nowLabel = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second:'2-digit' });

    lineChart30s.data.labels.push(nowLabel);
    lineChart30s.data.datasets[0].data.push(count);

    if (lineChart30s.data.labels.length > MAX_LINE_POINTS) {
        lineChart30s.data.labels.shift();
        lineChart30s.data.datasets[0].data.shift();
    }
    lineChart30s.update('none');
}

function updateBarChart(data) {
    barChartRules.data.datasets[0].data = [
        data.phishing || 0,
        data.dos || 0,
        data.crypto || 0,
        data.bruteforce || 0
    ];
    barChartRules.update();
}

function updateLicenseProgressBar(rawMB) {
    const mb = rawMB || 0;
    const limit = 500;
    
    let percent = Math.round((mb / limit) * 100);
    if (percent > 100) percent = 100;

    const progressBar = document.getElementById('license-progress-bar');
    const usedText = document.getElementById('license-used-text');

    usedText.textContent = `${mb} MB`;
    
    progressBar.style.height = `${percent}%`;
    progressBar.textContent = `${percent}%`;

    let newClass = 'bg-success';
    if (mb > 400) {
        newClass = 'bg-danger';
    } else if (mb > 350) {
        newClass = 'bg-orange'; 
    } else if (mb > 300) {
        newClass = 'bg-warning';
    }

    progressBar.classList.remove('bg-success', 'bg-warning', 'bg-orange', 'bg-danger');
    progressBar.classList.add(newClass);
}


// --- TABLE RENDERING FUNCTIONS ---
function getBadgeClass(type) {
    if (type === 'Phishing') return 'danger';
    if (type === 'DoS') return 'warning';
    if (type === 'Cryptojacking') return 'info';
    if (type === 'Brute Force') return 'primary';
    return 'secondary';
}

function getSeverityClass(severity) {
    severity = severity ? severity.toLowerCase() : 'unknown';
    if (severity === 'critical') return 'badge-critical';
    if (severity === 'high') return 'badge-high';
    if (severity === 'medium') return 'badge-medium';
    if (severity === 'low') return 'badge-low';
    return 'badge-unknown';
}

function renderTable(logs) {
    const tableBody = document.getElementById('log-table-body');
    if (logs.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-3">No recent events found.</td></tr>';
        return;
    }

    let tableRows = '';
    logs.forEach(log => {
        const typeColor = getBadgeClass(log.type);
        const sevColor = getSeverityClass(log.severity);

        tableRows += `
            <tr class="log-row">
                <td><small class="fw-bold">${log.time.split(' ')[1] || log.time}</small></td> <td><span class="badge ${sevColor}">${log.severity || 'Unknown'}</span></td>
                <td><span class="badge bg-${typeColor} text-dark">${log.type}</span></td>
                <td class="text-truncate" style="max-width: 120px;" title="${log.host}">${log.host}</td>
                <td class="text-truncate" style="max-width: 150px;" title="${log.source}">${log.source || '-'}</td>
                <td><small>${log.extra || '-'}</small></td>
                <td class="text-truncate" style="max-width: 200px;" title="${log.details}"><small>${log.details}</small></td>
                <td class="text-center">${log.alert ? '✅' : '❌'}</td>
            </tr>
        `;
    });
    tableBody.innerHTML = tableRows;
}

function sortTable(column) {
    if (sortState.column === column) {
        sortState.asc = !sortState.asc;
    } else {
        sortState.column = column;
        sortState.asc = true;
    }
    applySort();
}

function applySort() {
    const column = sortState.column;
    const asc = sortState.asc;

    currentLogs.sort((a, b) => {
        let valA = a[column] || '';
        let valB = b[column] || '';

        if (column === 'severity') {
            valA = getSeverityWeight(valA);
            valB = getSeverityWeight(valB);
        } 
        else if (typeof valA === 'string') {
            valA = valA.toLowerCase();
            valB = valB.toLowerCase();
        }

        if (valA < valB) return asc ? -1 : 1;
        if (valA > valB) return asc ? 1 : -1;
        return 0;
    });

    renderTable(currentLogs);
    updateSortIcons();
}

function getSeverityWeight(sev) {
    const map = {
        'Critical': 5,
        'High': 4,
        'Medium': 3,
        'Low': 2,
        'Unknown': 1
    };
    return map[sev] || 0;
}

function updateSortIcons() {
    document.querySelectorAll('th').forEach(th => {
        th.classList.remove('sorted-asc', 'sorted-desc');
    });

    const activeHeader = Array.from(document.querySelectorAll('th')).find(th => 
        th.getAttribute('onclick') && th.getAttribute('onclick').includes(`'${sortState.column}'`)
    );

    if (activeHeader) {
        activeHeader.classList.add(sortState.asc ? 'sorted-asc' : 'sorted-desc');
    }
}

function updateLicenseWarnings(warnings) {
    const container = document.getElementById('license-warning-container');
    const MAX_WARNINGS = 5; 
    
    if (!warnings || warnings.length === 0) {
        container.innerHTML = `
            <div class="alert py-2 px-3 small mb-0 border-0" style="background-color: rgba(25, 135, 84, 0.15); color: #75b798; border-radius: 8px;">
                <div class="fw-bold mb-1" style="font-size: 0.75rem; letter-spacing: 0.5px;">
                    <i class="ri-checkbox-circle-fill me-1"></i> QUOTA WARNING 0/${MAX_WARNINGS}
                </div>
                <div style="opacity: 0.9; line-height: 1.4;">
                    System Healthy. No overage reported.
                </div>
            </div>
        `;
    } else {
        let html = '';
        
        warnings.forEach((warnText, index) => {
            const countStr = `${index + 1}/${MAX_WARNINGS}`;
            
            html += `
                <div class="alert py-2 px-3 small mb-2 border-0" style="background-color: rgba(253, 199, 12, 0.15); color: #fdc70c; border-radius: 8px;">
                    <div class="fw-bold mb-1" style="font-size: 0.75rem; letter-spacing: 0.5px;">
                        <i class="ri-error-warning-fill me-1"></i> QUOTA WARNING ${countStr}
                    </div>
                    <div style="opacity: 0.9; line-height: 1.4;">
                        ${warnText}
                    </div>
                </div>
            `;
        });
        container.innerHTML = html;
    }
}

// --- THEME TOGGLE LOGIC ---
function toggleTheme() {
    const htmlTag = document.documentElement;
    const currentTheme = htmlTag.getAttribute('data-bs-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    htmlTag.setAttribute('data-bs-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    updateThemeIcon(newTheme);
}

function updateThemeIcon(theme) {
    const themeIcon = document.getElementById('theme-icon');
    if (themeIcon) {
        themeIcon.className = theme === 'dark' ? 'ri-sun-line' : 'ri-moon-line';
    }
}