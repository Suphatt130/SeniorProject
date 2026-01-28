// Global Variables
let attackChart;
let currentFilter = 'all';

document.addEventListener("DOMContentLoaded", () => {
    initChart();       // Setup the empty chart
    fetchData();       // First data fetch
    setInterval(fetchData, 5000); // Auto-refresh loop
});

// 1. Initialize Chart.js
function initChart() {
    const ctx = document.getElementById('liveChart');
    if (!ctx) return; // Safety check

    attackChart = new Chart(ctx.getContext('2d'), {
        type: 'line',
        data: {
            labels: [], 
            datasets: [{
                label: 'Total Threats Detected',
                data: [], 
                borderColor: '#ff4d4d', 
                backgroundColor: 'rgba(255, 77, 77, 0.2)', 
                borderWidth: 2,
                fill: true,
                tension: 0.4 
            }]
        },
        options: {
            responsive: true,
            scales: {
                x: { ticks: { color: '#ccc' } },
                y: { ticks: { color: '#ccc' }, beginAtZero: true }
            },
            plugins: {
                legend: { labels: { color: '#fff' } }
            }
        }
    });
}

// 2. Update Chart with New Data
function updateChart(totalCount) {
    if (!attackChart) return;

    const now = new Date().toLocaleTimeString();
    
    attackChart.data.labels.push(now);
    attackChart.data.datasets[0].data.push(totalCount);

    if (attackChart.data.labels.length > 20) {
        attackChart.data.labels.shift();
        attackChart.data.datasets[0].data.shift();
    }
    attackChart.update();
}

// 3. Main Data Fetcher
function fetchData() {
    // A. Get Stats
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            if (data.error) return;
            
            // Update Card Numbers
            if(document.getElementById('count-total')) document.getElementById('count-total').innerText = data.total || 0;
            if(document.getElementById('count-phishing')) document.getElementById('count-phishing').innerText = data.phishing || 0;
            if(document.getElementById('count-ddos')) document.getElementById('count-ddos').innerText = data.ddos || 0;
            if(document.getElementById('count-crypto')) document.getElementById('count-crypto').innerText = data.crypto || 0;
            if(document.getElementById('count-bruteforce')) document.getElementById('count-bruteforce').innerText = data.bruteforce || 0;
            if(document.getElementById('count-license')) document.getElementById('count-license').innerText = data.license || 0;

            // Update Graph
            updateChart(data.total);
        })
        .catch(err => console.error("Stats Error:", err));

    // B. Get Logs Table
    fetch('/api/logs')
        .then(response => response.json())
        .then(data => {
            if (data.error) return;
            
            const tableBody = document.getElementById('log-table-body');
            if (!tableBody) return;

            tableBody.innerHTML = ""; 

            data.forEach(log => {
                // Determine Type Badge Color
                let badgeClass = 'secondary';
                if (log.type === 'Phishing') badgeClass = 'danger';
                if (log.type === 'DDoS') badgeClass = 'warning';
                if (log.type === 'Cryptojacking') badgeClass = 'info';
                if (log.type === 'Brute Force') badgeClass = 'dark'; 
                if (log.type === 'License Warning') badgeClass = 'primary';

                // Determine Severity Badge Color
                let sevColor = 'secondary';
                if (log.severity === 'Critical') sevColor = 'danger'; // Red
                if (log.severity === 'High') sevColor = 'warning';    // Orange
                if (log.severity === 'Medium') sevColor = 'info';     // Blue
                if (log.severity === 'Low') sevColor = 'success';     // Green

                // Brute Force Badge styling fix
                const badgeStyle = (log.type === 'Brute Force') ? 'background-color: #6f42c1;' : '';
                
                // Filter Logic
                const displayStyle = (currentFilter === 'all' || log.type === currentFilter) ? '' : 'none';

                const row = `
                    <tr class="log-row" data-type="${log.type}" style="display: ${displayStyle};">
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
        })
        .catch(err => console.error("Logs Error:", err));
}

// 4. Filter Function (Called when clicking cards)
function filterTable(type) {
    currentFilter = type;
    const rows = document.querySelectorAll('.log-row');
    rows.forEach(row => {
        const rowType = row.getAttribute('data-type');
        if (type === 'all' || rowType === type) {
            row.style.display = ''; 
        } else {
            row.style.display = 'none'; 
        }
    });
}