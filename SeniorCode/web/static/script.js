let attackChart;
let currentFilter = 'all';
let allLogsData = [];
let sortDirection = { time: 'desc', severity: 'desc', type: 'asc', host: 'asc' };

document.addEventListener("DOMContentLoaded", () => {
    initChart();       
    fetchData();       
    setInterval(fetchData, 5000);
});

// 1. Initialize Chart.js
function initChart() {
    const ctx = document.getElementById('liveChart');
    if (!ctx) return;

    attackChart = new Chart(ctx.getContext('2d'), {
        type: 'line',
        data: {
            labels: [], 
            datasets: [{
                label: 'Threat Intensity',
                data: [], 
                borderColor: '#ff4d4d', 
                backgroundColor: 'rgba(255, 77, 77, 0.2)',
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointRadius: 3,
                pointHoverRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { 
                    ticks: { color: '#aaa', maxTicksLimit: 8 },
                    grid: { color: 'rgba(255, 255, 255, 0.05)' } 
                },
                y: { 
                    ticks: { color: '#aaa', stepSize: 1 }, 
                    beginAtZero: true,
                    grid: { color: 'rgba(255, 255, 255, 0.05)' }
                }
            },
            plugins: {
                legend: { display: false }
            },
            animation: { duration: 0 }
        }
    });
}

function updateChart(totalCount) {
    if (!attackChart) return;

    const now = new Date().toLocaleTimeString();
    
    attackChart.data.labels.push(now);
    attackChart.data.datasets[0].data.push(totalCount);

    if (attackChart.data.labels.length > 15) {
        attackChart.data.labels.shift();
        attackChart.data.datasets[0].data.shift();
    }
    attackChart.update();
}

// 2. Data Fetcher
function fetchData() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            if (data.error) return;
            
            // Standard Counters
            if(document.getElementById('count-total')) document.getElementById('count-total').innerText = data.total || 0;
            if(document.getElementById('count-phishing')) document.getElementById('count-phishing').innerText = data.phishing || 0;
            if(document.getElementById('count-ddos')) document.getElementById('count-ddos').innerText = data.ddos || 0;
            if(document.getElementById('count-crypto')) document.getElementById('count-crypto').innerText = data.crypto || 0;
            if(document.getElementById('count-bruteforce')) document.getElementById('count-bruteforce').innerText = data.bruteforce || 0;

            if(document.getElementById('count-license')) {
                document.getElementById('count-license').innerText = data.license_text || "0 / 500 MB";
                document.getElementById('count-license').style.fontSize = "1.5rem";
            }

            updateChart(data.total);
        })
        .catch(err => console.error("Stats Error:", err));

    // B. Get Logs Table
    fetch('/api/logs')
        .then(response => response.json())
        .then(data => {
            if (data.error) return;
            
            allLogsData = data; 
            
            renderTable(allLogsData);
        })
        .catch(err => console.error("Logs Error:", err));
}

// 3. Render Table Function
function renderTable(data) {
    const tableBody = document.getElementById('log-table-body');
    if (!tableBody) return;

    tableBody.innerHTML = ""; 

    data.forEach(log => {
        // Filter Logic
        if (currentFilter !== 'all' && log.type !== currentFilter) return;

        // Badge Logic
        let badgeClass = 'secondary';
        if (log.type === 'Phishing') badgeClass = 'danger';
        if (log.type === 'DoS / Flood') badgeClass = 'warning';
        if (log.type === 'Cryptojacking') badgeClass = 'info';
        if (log.type === 'Brute Force') badgeClass = 'dark'; 
        if (log.type === 'License Warning') badgeClass = 'primary';

        let sevColor = 'secondary';
        if (log.severity === 'Critical') sevColor = 'danger'; 
        if (log.severity === 'High') sevColor = 'warning';    
        if (log.severity === 'Medium') sevColor = 'info';     
        if (log.severity === 'Low') sevColor = 'success';     

        const badgeStyle = (log.type === 'Brute Force') ? 'background-color: #6f42c1;' : '';
        
        const row = `
            <tr class="log-row">
                <td><small>${log.time}</small></td>
                <td><span class="badge bg-${sevColor}">${log.severity || 'Unknown'}</span></td>
                <td><span class="badge bg-${badgeClass}" style="${badgeStyle}">${log.type}</span></td>
                <td>${log.host}</td>
                <td><small>${log.source || '-'}</small></td>
                <td><small>${log.extra}</small></td>
                <td><small>${log.details}</small></td>
                <td>${log.alert ? '✅' : '❌'}</td>
            </tr>
        `;
        tableBody.innerHTML += row;
    });
}

// 4. Sorting Function
function sortTable(key) {
    sortDirection[key] = sortDirection[key] === 'asc' ? 'desc' : 'asc';
    const direction = sortDirection[key];

    const severityMap = { 'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Unknown': 0 };

    allLogsData.sort((a, b) => {
        let valA = a[key];
        let valB = b[key];

        if (key === 'severity') {
            valA = severityMap[valA] || 0;
            valB = severityMap[valB] || 0;
        }

        if (valA < valB) return direction === 'asc' ? -1 : 1;
        if (valA > valB) return direction === 'asc' ? 1 : -1;
        return 0;
    });

    renderTable(allLogsData);
}

// 5. Filter Function
function filterTable(type) {
    currentFilter = type;
    renderTable(allLogsData);
}