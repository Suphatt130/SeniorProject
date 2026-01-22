// Global Variables for Chart
let attackChart;
let currentFilter = 'all';

document.addEventListener("DOMContentLoaded", () => {
    initChart();       // Setup the empty chart
    fetchData();       // First data fetch
    setInterval(fetchData, 5000); // Auto-refresh loop
});

// 1. Initialize Chart.js
function initChart() {
    const ctx = document.getElementById('liveChart').getContext('2d');
    attackChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [], // Time labels
            datasets: [{
                label: 'Total Threats Detected',
                data: [], // Data points
                borderColor: '#ff4d4d', // Red line
                backgroundColor: 'rgba(255, 77, 77, 0.2)', // Red glow area
                borderWidth: 2,
                fill: true,
                tension: 0.4 // Smooth curves
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
    const now = new Date().toLocaleTimeString();
    
    // Add new data point
    attackChart.data.labels.push(now);
    attackChart.data.datasets[0].data.push(totalCount);

    // Keep chart clean: Remove old points if more than 20
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
            document.getElementById('count-total').innerText = data.total || 0;
            document.getElementById('count-phishing').innerText = data.phishing || 0;
            document.getElementById('count-ddos').innerText = data.ddos || 0;
            document.getElementById('count-crypto').innerText = data.crypto || 0;
            
            const bf = document.getElementById('count-bruteforce');
            if(bf) bf.innerText = data.bruteforce || 0;

            const lic = document.getElementById('count-license'); // License Card
            if(lic && data.license) lic.innerText = data.license || 0;

            // Update Graph
            updateChart(data.total);
        });

    // B. Get Logs Table
    fetch('/api/logs')
        .then(response => response.json())
        .then(data => {
            if (data.error) return;
            
            const tableBody = document.getElementById('log-table-body');
            tableBody.innerHTML = ""; 

            data.forEach(log => {
                let badgeClass = 'secondary';
                if (log.type === 'Phishing') badgeClass = 'danger';
                if (log.type === 'DDoS') badgeClass = 'warning';
                if (log.type === 'Cryptojacking') badgeClass = 'info';
                if (log.type === 'Brute Force') badgeClass = 'dark'; // Purple-ish default
                if (log.type === 'License Warning') badgeClass = 'primary';

                // We add a 'data-type' attribute to the row for filtering
                // Display: 'none' if it doesn't match current filter
                const displayStyle = (currentFilter === 'all' || log.type === currentFilter) ? '' : 'none';

                // Fix Brute Force badge color manually if needed
                const badgeStyle = (log.type === 'Brute Force') ? 'background-color: #6f42c1;' : '';

                const row = `
                    <tr class="log-row" data-type="${log.type}" style="display: ${displayStyle};">
                        <td><small>${log.time}</small></td>
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
        });
}

// 4. Filter Function (Called when clicking cards)
function filterTable(type) {
    currentFilter = type;
    
    // Get all rows
    const rows = document.querySelectorAll('.log-row');
    
    rows.forEach(row => {
        const rowType = row.getAttribute('data-type');
        
        if (type === 'all' || rowType === type) {
            row.style.display = ''; // Show
        } else {
            row.style.display = 'none'; // Hide
        }
    });
}