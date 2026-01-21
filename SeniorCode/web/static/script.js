document.addEventListener("DOMContentLoaded", () => {
    fetchData(); 
    setInterval(fetchData, 5000); 
});

function fetchData() {
    // 1. Get Summary Stats
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            if (data.error) return;
            document.getElementById('count-total').innerText = data.total || 0;
            document.getElementById('count-phishing').innerText = data.phishing || 0;
            document.getElementById('count-ddos').innerText = data.ddos || 0;
            document.getElementById('count-crypto').innerText = data.crypto || 0;
            // Add BruteForce if you added the card in HTML
            const bf = document.getElementById('count-bruteforce');
            if(bf) bf.innerText = data.bruteforce || 0;
        });

    // 2. Get Logs Table
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
                if (log.type === 'Brute Force') badgeClass = 'dark';

                const row = `
                    <tr>
                        <td><small>${log.time}</small></td>
                        <td><span class="badge bg-${badgeClass}">${log.type}</span></td>
                        <td>${log.host}</td>
                        <td><small>${log.details}</small></td>
                        <td><small>${log.extra}</small></td>
                        <td>${log.alert ? '✅' : '❌'}</td>
                    </tr>
                `;
                tableBody.innerHTML += row;
            });
        });
}