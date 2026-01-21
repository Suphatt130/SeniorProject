document.addEventListener("DOMContentLoaded", () => {
    fetchData(); // Run once immediately
    setInterval(fetchData, 5000); // Auto-refresh every 5 seconds
});

function fetchData() {
    // 1. Get Summary Stats
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            if (data.error) return; // Skip if error
            document.getElementById('count-total').innerText = data.total;
            document.getElementById('count-phishing').innerText = data.phishing;
            document.getElementById('count-ddos').innerText = data.ddos;
            document.getElementById('count-crypto').innerText = data.crypto;
            document.getElementById('count-bruteforce').innerText = data.bruteforce;
        });

    // 2. Get Logs Table
    fetch('/api/logs')
        .then(response => response.json())
        .then(data => {
            if (data.error) return;
            
            const tableBody = document.getElementById('log-table-body');
            tableBody.innerHTML = ""; // Clear old rows

            data.forEach(log => {
                // Determine badge color based on attack type
                let badgeClass = 'secondary';
                if (log.attack_type === 'Phishing') badgeClass = 'danger';
                if (log.attack_type === 'DDoS') badgeClass = 'warning';
                if (log.attack_type === 'Cryptojacking') badgeClass = 'info';
                if (log.attack_type === 'Brute Force') badgeClass = 'dark';

                const row = `
                    <tr>
                        <td><small>${log.timestamp}</small></td>
                        <td><span class="badge bg-${badgeClass}">${log.attack_type}</span></td>
                        <td>${log.computer}</td>
                        <td>${log.source_app || '-'}</td>
                        <td><small>${log.technique_id || '-'}</small></td>
                        <td><small>${log.details}</small></td>
                        <td>${log.alert_sent ? '✅' : '❌'}</td>
                    </tr>
                `;
                tableBody.innerHTML += row;
            });
        });
}