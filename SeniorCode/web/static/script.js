let lineChart30s, barChartRules;
let previousTotalLogs = null; 
const MAX_LINE_POINTS = 20; 

let currentLogs = []; 
let sortState = { column: 'time', asc: false }

// --- 1. INITIALIZE FUNCTIONS ON PAGE LOAD ---
document.addEventListener('DOMContentLoaded', () => {
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

async function fetchData() {
    const badge = document.getElementById('last-update-badge');
    if(badge) badge.textContent = 'Updating...';
    if(badge) badge.classList.replace('bg-primary', 'bg-secondary');

    try {
        const [statsRes, logsRes] = await Promise.all([
            fetch('/api/stats'),
            fetch('/api/logs')
        ]);

        const statsData = await statsRes.json();
        const logsData = await logsRes.json();
        
        if (statsData.error) console.error("Stats Error:", statsData.error);
        if (logsData.error) console.error("Logs Error:", logsData.error);
        
        updateTopCards(statsData);
        updateLineChart(statsData.logs_last_30s);
        updateBarChart(statsData);
        updateLicenseProgressBar(statsData.license_mb_raw);
        currentLogs = logsData;
        applySort();

        if(badge) badge.textContent = 'Live';
        if(badge) badge.classList.replace('bg-secondary', 'bg-primary');

    } catch (err) {
        console.error("Fetch Error:", err);
        if(badge) badge.textContent = 'Error';
        if(badge) badge.classList.replace('bg-secondary', 'bg-danger');
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
    if (mb > 500) {
        newClass = 'bg-danger';
    } else if (mb > 450) {
        newClass = 'bg-orange'; 
    } else if (mb > 400) {
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
    severity = severity.toLowerCase();
    if (severity === 'critical') return 'danger';
    if (severity === 'high') return 'warning';
    if (severity === 'medium') return 'info';
    if (severity === 'low') return 'success';
    return 'secondary';
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
                <td><small class="fw-bold">${log.time.split(' ')[1] || log.time}</small></td> <td><span class="badge bg-${sevColor} text-dark">${log.severity || 'Unknown'}</span></td>
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