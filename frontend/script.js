// API Configuration
const API_BASE = 'http://localhost:5000/api';

class FakeAPKDetector {
    constructor() {
        this.initializeElements();
        this.attachEventListeners();
        this.loadScanHistory();
        this.updateStats();
        this.initChart();
    }

    initializeElements() {
        this.uploadArea = document.getElementById('uploadArea');
        this.fileInput = document.getElementById('fileInput');
        this.resultsSection = document.getElementById('resultsSection');
        this.riskScore = document.getElementById('riskScore');
        this.riskLabel = document.getElementById('riskLabel');
        this.resultDetails = document.getElementById('resultDetails');
        this.historyList = document.getElementById('historyList');
        this.totalScans = document.getElementById('totalScans');
        this.successRate = document.getElementById('successRate');
        this.refreshBtn = document.getElementById('refreshBtn');
    }

    attachEventListeners() {
        this.uploadArea.addEventListener('click', () => this.fileInput.click());
        this.fileInput.addEventListener('change', (e) => this.handleFileSelect(e));
        this.uploadArea.addEventListener('dragover', (e) => this.handleDragOver(e));
        this.uploadArea.addEventListener('dragleave', (e) => this.handleDragLeave(e));
        this.uploadArea.addEventListener('drop', (e) => this.handleFileDrop(e));
        this.refreshBtn.addEventListener('click', () => this.loadScanHistory());
    }

    handleDragOver(e) { e.preventDefault(); this.uploadArea.classList.add('dragover'); }
    handleDragLeave(e) { e.preventDefault(); this.uploadArea.classList.remove('dragover'); }
    handleFileDrop(e) {
        e.preventDefault();
        this.uploadArea.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) this.handleFile(e.dataTransfer.files[0]);
    }
    handleFileSelect(e) {
        if (e.target.files[0]) this.handleFile(e.target.files[0]);
    }

    async handleFile(file) {
        if (!file.name.endsWith('.apk')) { this.showAlert('Please select a valid APK file.', 'error'); return; }
        if (file.size > 250 * 1024 * 1024) { this.showAlert('File size exceeds 100MB limit.', 'error'); return; }
        this.showAnalyzing();

        try {
            const formData = new FormData();
            formData.append('file', file);
            const response = await fetch(`${API_BASE}/upload`, { method: 'POST', body: formData });
            if (!response.ok) throw new Error((await response.json()).error || 'Upload failed');
            const result = await response.json();
            console.log('API Result:', result);
            this.displayResults(result);
            this.loadScanHistory();
            this.updateStats();
            this.showAlert(`APK analyzed successfully! Risk score: ${result.risk_score}/100`, 'success');
            this.fileInput.value = '';
        } catch (error) {
            console.error(error);
            this.showAlert(`Error analyzing APK: ${error.message}`, 'error');
            this.hideResults();
            this.fileInput.value = '';
        }
    }

    showAnalyzing() {
        this.resultsSection.style.display = 'block';
        this.riskScore.textContent = '...';
        this.riskScore.className = 'risk-score analyzing';
        this.riskLabel.textContent = 'ANALYZING...';
        this.riskLabel.className = 'risk-label';
        this.resultDetails.innerHTML = '<div class="loading">🔍 Analyzing APK file...</div>';
        this.resultsSection.scrollIntoView({ behavior: 'smooth' });
    }

    displayResults(result) {
        this.resultsSection.style.display = 'block';
        this.riskScore.textContent = result.risk_score;
        this.riskScore.classList.remove('analyzing');

        if (result.risk_score < 30) {
            this.riskScore.className = 'risk-score safe';
            this.riskLabel.className = 'risk-label safe';
            this.riskLabel.textContent = '✅ SAFE';
        } else if (result.risk_score < 70) {
            this.riskScore.className = 'risk-score warning';
            this.riskLabel.className = 'risk-label warning';
            this.riskLabel.textContent = '⚠️ SUSPICIOUS';
        } else {
            this.riskScore.className = 'risk-score danger';
            this.riskLabel.className = 'risk-label danger';
            this.riskLabel.textContent = '🚨 DANGEROUS';
        }

        this.resultDetails.innerHTML = this.buildResultDetails(result);
    }

    buildResultDetails(result) {
        const analysis = result.analysis || {};
        const cert = analysis.certificate || {};
        const ml = analysis.ml_prediction || {};
        const mlPkg = analysis.ml_features?.package || {};

        return `
            <div class="detail-item"><span class="detail-label">📱 App Name:</span>
                <span class="detail-value">${analysis.app_name || 'Unknown'}</span></div>

            <div class="detail-item"><span class="detail-label">📦 Package:</span>
                <span class="detail-value">${analysis.package_name || 'Unknown'}</span></div>

            <div class="detail-item"><span class="detail-label">📊 File Size:</span>
                <span class="detail-value">${this.formatFileSize(analysis.file_size)}</span></div>

            <div class="detail-item"><span class="detail-label">🆔 App Version:</span>
                <span class="detail-value">${mlPkg.app_version || 'Unknown'}</span></div>

            <div class="detail-item"><span class="detail-label">📱 SDK (min/target):</span>
                <span class="detail-value">${analysis.min_sdk || 'N/A'} / ${analysis.target_sdk || 'N/A'}</span></div>

            <div class="detail-item"><span class="detail-label">🔐 Total Permissions:</span>
                <span class="detail-value">${analysis.permissions?.length || 0}</span></div>

            <div class="detail-item"><span class="detail-label">⚠️ Dangerous Permissions:</span>
                <span class="detail-value" style="color: ${analysis.dangerous_permissions?.length > 3 ? '#ef4444' : '#10b981'}">
                    ${analysis.dangerous_permissions?.length || 0}
                </span></div>

            <div class="detail-item"><span class="detail-label">🔏 Certificate Issuer:</span>
                <span class="detail-value">${cert.issuer || 'Unknown'}</span></div>

            <div class="detail-item"><span class="detail-label">📜 Cert Validity:</span>
                <span class="detail-value">${cert.not_before || 'N/A'} → ${cert.not_after || 'N/A'}</span></div>

            <div class="detail-item"><span class="detail-label">🔑 Key Size:</span>
                <span class="detail-value">${cert.key_size || 'N/A'} bits</span></div>

            <div class="detail-item"><span class="detail-label">🤖 ML Confidence:</span>
                <span class="detail-value">${(ml.confidence * 100 || 0).toFixed(2)}%</span></div>

            <div class="detail-item"><span class="detail-label">📊 ML Breakdown:</span>
                <span class="detail-value">Pkg: ${(ml.pkg_confidence*100).toFixed(2)}% |
                Perms: ${(ml.perm_confidence*100).toFixed(2)}% |
                Cert: ${(ml.cert_confidence*100).toFixed(2)}%</span></div>

            <div class="detail-item"><span class="detail-label">🆔 File Hash:</span>
                <span class="detail-value" style="font-family: monospace; font-size: 0.8em;">
                    ${analysis.file_hash ? analysis.file_hash.substring(0, 16) + '...' : 'N/A'}
                </span></div>

            <div class="detail-item"><span class="detail-label">⏰ Scan Time:</span>
                <span class="detail-value">${new Date(result.timestamp).toLocaleString()}</span></div>
        `;
    }


    async loadScanHistory() {
        try {
            this.historyList.innerHTML = '<div class="loading">🔄 Loading scan history...</div>';
            const response = await fetch(`${API_BASE}/scans`);
            if (!response.ok) throw new Error('Failed to load scan history');
            const data = await response.json();
            if (data.scans?.length) this.displayScanHistory(data.scans);
            else this.historyList.innerHTML = '<div class="loading">📋 No scan history available.</div>';
        } catch (error) {
            console.error(error);
            this.historyList.innerHTML = '<div class="loading">❌ Error loading scan history.</div>';
        }
    }

    displayScanHistory(scans) {
        const historyHTML = scans.map(scan => {
            const riskColor = scan.risk_score < 30 ? '#10b981' : scan.risk_score < 70 ? '#f59e0b' : '#ef4444';
            const riskEmoji = scan.risk_score < 30 ? '✅' : scan.risk_score < 70 ? '⚠️' : '🚨';
            return `
                <div class="history-item">
                    <div class="history-filename">
                        ${riskEmoji} ${scan.filename}
                    </div>
                    <div class="history-risk" style="background-color: ${riskColor}20; color: ${riskColor};">
                        ${scan.risk_score}/100
                    </div>
                    <div class="history-timestamp">
                        ${new Date(scan.timestamp).toLocaleDateString()} ${new Date(scan.timestamp).toLocaleTimeString()}
                    </div>
                </div>
            `;
        }).join('');
        this.historyList.innerHTML = historyHTML;
    }

    async updateStats() {
        try {
            const response = await fetch(`${API_BASE}/scans`);
            if (!response.ok) throw new Error('Failed to load stats');
            const data = await response.json();
            if (!data.scans) return;

            const totalScans = data.scans.length;
            const successRate = totalScans > 0 ? Math.round(totalScans / totalScans * 100) : 100;

            this.animateCounter(this.totalScans, totalScans);
            this.successRate.textContent = `${successRate}%`;
            this.updateChart(data.scans);
        } catch (error) {
            console.error(error);
        }
    }

    animateCounter(element, targetValue) {
        const currentValue = parseInt(element.textContent) || 0;
        if (currentValue === targetValue) return;
        const diff = targetValue - currentValue;
        const steps = Math.abs(diff);
        const step = diff / steps;
        const stepDuration = 1000 / Math.max(steps, 1);
        let current = currentValue;
        const timer = setInterval(() => {
            current += step;
            element.textContent = Math.round(current);
            if ((step > 0 && current >= targetValue) || (step < 0 && current <= targetValue)) {
                element.textContent = targetValue;
                clearInterval(timer);
            }
        }, stepDuration);
    }

    initChart() {
        const ctx = document.getElementById('riskChart').getContext('2d');
        this.chart = new Chart(ctx, {
            type: 'line',
            data: { labels: [], datasets: [{ label: 'Risk Score', data: [], borderColor: '#667eea', backgroundColor: 'rgba(102, 126, 234, 0.1)', tension: 0.4, fill: true }] },
            options: { responsive: true }
        });
    }

    updateChart(scans) {
        if (!this.chart) return;
        const last10 = scans.slice(0, 10).reverse();
        this.chart.data.labels = last10.map(s => `${new Date(s.timestamp).getMonth() + 1}/${new Date(s.timestamp).getDate()}`);
        this.chart.data.datasets[0].data = last10.map(s => s.risk_score);
        this.chart.update();
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return (bytes / Math.pow(k, i)).toFixed(2) + ' ' + sizes[i];
    }

    showAlert(message, type = 'success') {
        const existing = document.querySelector('.alert');
        if (existing) existing.remove();
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type}`;
        alertDiv.textContent = message;
        document.querySelector('.container').insertBefore(alertDiv, document.querySelector('main'));
        setTimeout(() => alertDiv.remove(), 5000);
    }

    hideResults() { this.resultsSection.style.display = 'none'; }
}

document.addEventListener('DOMContentLoaded', () => new FakeAPKDetector());
