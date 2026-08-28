/**
 * OsintPro - Web Interface JavaScript
 */

// Theme Management
const themeToggle = document.getElementById('themeToggle');
const html = document.documentElement;

// Check for saved theme preference or default to light
const savedTheme = localStorage.getItem('theme') || 'light';
html.setAttribute('data-theme', savedTheme);
updateThemeIcon(savedTheme);

themeToggle.addEventListener('click', () => {
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    
    html.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    updateThemeIcon(newTheme);
});

function updateThemeIcon(theme) {
    const icon = themeToggle.querySelector('.theme-icon');
    const text = themeToggle.querySelector('.theme-text');
    icon.textContent = theme === 'light' ? '🌙' : '☀️';
    text.textContent = theme === 'light' ? 'Oscuro' : 'Claro';
}

// Navigation
const navLinks = document.querySelectorAll('.nav-link');
const sections = document.querySelectorAll('.section');

navLinks.forEach(link => {
    link.addEventListener('click', () => {
        const target = link.getAttribute('data-section');
        
        // Update active nav
        navLinks.forEach(l => l.classList.remove('active'));
        link.classList.add('active');
        
        // Show target section
        sections.forEach(s => s.classList.remove('active'));
        document.getElementById(target).classList.add('active');
    });
});

// API Helper
async function apiCall(endpoint, data) {
    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data)
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

// Show/Hide Loading
function showLoading(elementId) {
    const element = document.getElementById(elementId);
    if (element) element.classList.add('show');
}

function hideLoading(elementId) {
    const element = document.getElementById(elementId);
    if (element) element.classList.remove('show');
}

// Show Results
function showResults(elementId, data, type) {
    const container = document.getElementById(elementId);
    container.innerHTML = '';
    container.classList.add('show');
    
    const resultCard = document.createElement('div');
    resultCard.className = 'result-card';
    
    // Determine risk level
    let riskLevel = 'low';
    let riskText = 'BAJO';
    if (data.overall_risk === 'HIGH' || data.risk_score >= 3) {
        riskLevel = 'high';
        riskText = 'ALTO';
    } else if (data.overall_risk === 'MEDIUM' || data.risk_score >= 1) {
        riskLevel = 'medium';
        riskText = 'MEDIO';
    }
    
    let html = `
        <div class="result-header">
            <div class="result-status">
                <span>Riesgo:</span>
                <span class="status-badge status-${riskLevel}">${riskText}</span>
            </div>
        </div>
    `;
    
    // Add specific results based on type
    if (type === 'crypto') {
        html += renderCryptoResults(data);
    } else if (type === 'url') {
        html += renderURLResults(data);
    } else if (type === 'email') {
        html += renderEmailResults(data);
    } else if (type === 'domain') {
        html += renderDomainResults(data);
    } else if (type === 'whois') {
        html += renderWHOISResults(data);
    } else if (type === 'project') {
        html += renderProjectResults(data);
    } else if (type === 'breach') {
        html += renderBreachResults(data);
    }
    
    resultCard.innerHTML = html;
    container.appendChild(resultCard);
}

function renderCryptoResults(data) {
    const balance = data.balance || {};
    const balanceEth = balance.balance_eth || 0;
    const balanceBtc = balance.balance_btc || 0;
    const txCount = data.recent_transactions?.count || 0;
    
    return `
        <div class="result-grid">
            <div class="result-item">
                <div class="result-label">Red</div>
                <div class="result-value">${data.network || 'N/A'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Balance</div>
                <div class="result-value">${balanceEth > 0 ? balanceEth.toFixed(6) + ' ETH' : balanceBtc > 0 ? balanceBtc.toFixed(8) + ' BTC' : '0'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Transacciones</div>
                <div class="result-value">${txCount}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Direccion</div>
                <div class="result-value" style="font-size: 0.8rem; word-break: break-all;">${data.address || 'N/A'}</div>
            </div>
        </div>
        ${renderIndicators(data.risk_indicators || [], 'Indicadores de Riesgo')}
    `;
}

function renderURLResults(data) {
    const structure = data.structure_analysis || {};
    
    return `
        <div class="result-grid">
            <div class="result-item">
                <div class="result-label">Dominio</div>
                <div class="result-value">${structure.domain || 'N/A'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">HTTPS</div>
                <div class="result-value">${structure.uses_https ? '✓ Si' : '✗ No'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Longitud URL</div>
                <div class="result-value">${structure.url_length || 0} caracteres</div>
            </div>
            <div class="result-item">
                <div class="result-label">Score Riesgo</div>
                <div class="result-value">${data.risk_score || 0}</div>
            </div>
        </div>
        ${renderIndicators(data.suspicious_indicators || [], 'Indicadores Sospechosos')}
    `;
}

function renderEmailResults(data) {
    const validation = data.validation || {};
    
    return `
        <div class="result-grid">
            <div class="result-item">
                <div class="result-label">Email</div>
                <div class="result-value">${data.email || 'N/A'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Formato Valido</div>
                <div class="result-value">${validation.is_valid_format ? '✓ Si' : '✗ No'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Email Desechable</div>
                <div class="result-value">${validation.is_disposable ? '⚠️ Si' : '✓ No'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Score Riesgo</div>
                <div class="result-value">${validation.risk_score || 0}</div>
            </div>
        </div>
        ${renderIndicators(validation.suspicious_indicators || [], 'Indicadores Sospechosos')}
    `;
}

function renderDomainResults(data) {
    const whois = data.whois || {};
    const ssl = data.ssl || {};
    
    return `
        <div class="result-grid">
            <div class="result-item">
                <div class="result-label">Dominio</div>
                <div class="result-value">${data.domain || 'N/A'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Registrador</div>
                <div class="result-value">${whois.registrar || 'N/A'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Edad (dias)</div>
                <div class="result-value">${whois.domain_age_days || 'N/A'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">SSL</div>
                <div class="result-value">${ssl.valid ? (ssl.is_expired ? '⚠️ Expirado' : '✓ Valido') : '✗ No valido'}</div>
            </div>
        </div>
        ${renderIndicators(data.risk_factors || [], 'Factores de Riesgo')}
    `;
}

function renderWHOISResults(data) {
    if (data.status_code === 'error') {
        return `<div class="result-item"><div class="result-value">Error: ${data.error}</div></div>`;
    }
    
    return `
        <div class="result-grid">
            <div class="result-item">
                <div class="result-label">Dominio</div>
                <div class="result-value">${data.domain || 'N/A'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Registrador</div>
                <div class="result-value">${data.registrar || 'N/A'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Creacion</div>
                <div class="result-value">${data.creation_date || 'N/A'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Expiracion</div>
                <div class="result-value">${data.expiration_date || 'N/A'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Edad</div>
                <div class="result-value">${data.domain_age_days ? data.domain_age_days + ' dias' : 'N/A'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Pais</div>
                <div class="result-value">${data.registrant?.country || 'N/A'}</div>
            </div>
        </div>
    `;
}

function renderProjectResults(data) {
    return `
        <div class="result-grid">
            <div class="result-item">
                <div class="result-label">Proyecto</div>
                <div class="result-value">${data.project_name || 'N/A'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Score Riesgo</div>
                <div class="result-value">${data.risk_score || 0}</div>
            </div>
        </div>
        ${renderIndicators(data.red_flags || [], 'Banderas Rojas', true)}
        ${renderIndicators(data.green_flags || [], 'Banderas Verdes', false, true)}
    `;
}

function renderBreachResults(data) {
    const hibp = data.hibp || {};
    
    return `
        <div class="result-grid">
            <div class="result-item">
                <div class="result-label">Email</div>
                <div class="result-value">${data.email || 'N/A'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Encontrado en Brechas</div>
                <div class="result-value">${hibp.found ? '⚠️ Si (' + hibp.breach_count + ')' : '✓ No'}</div>
            </div>
        </div>
        ${hibp.breaches ? renderBreachList(hibp.breaches) : ''}
    `;
}

function renderBreachList(breaches) {
    if (!breaches || breaches.length === 0) return '';
    
    let html = '<div class="result-list"><div class="result-label" style="margin-bottom: 0.5rem;">Brechas Encontradas:</div>';
    
    breaches.slice(0, 5).forEach(breach => {
        html += `
            <div class="result-list-item">
                <span class="result-list-icon">⚠️</span>
                <div>
                    <strong>${breach.name}</strong>
                    <div style="font-size: 0.85rem; color: var(--text-muted);">
                        Fecha: ${breach.breach_date || 'N/A'} | 
                        Registros: ${breach.pwn_count ? breach.pwn_count.toLocaleString() : 'N/A'}
                    </div>
                </div>
            </div>
        `;
    });
    
    html += '</div>';
    return html;
}

function renderIndicators(indicators, title, isDanger = true, isSuccess = false) {
    if (!indicators || indicators.length === 0) return '';
    
    let html = `<div class="result-list"><div class="result-label" style="margin-bottom: 0.5rem;">${title}:</div>`;
    
    indicators.forEach(indicator => {
        const iconClass = isSuccess ? 'success' : '';
        const icon = isSuccess ? '✓' : (isDanger ? '⚠️' : 'ℹ️');
        html += `
            <div class="result-list-item">
                <span class="result-list-icon ${iconClass}">${icon}</span>
                <span>${indicator}</span>
            </div>
        `;
    });
    
    html += '</div>';
    return html;
}

// Form Handlers

// Crypto Check
document.getElementById('cryptoForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const address = document.getElementById('cryptoAddress').value;
    
    showLoading('cryptoLoading');
    document.getElementById('cryptoResults').classList.remove('show');
    
    try {
        const result = await apiCall('/api/crypto/check', { address });
        hideLoading('cryptoLoading');
        showResults('cryptoResults', result, 'crypto');
    } catch (error) {
        hideLoading('cryptoLoading');
        alert('Error al analizar la direccion: ' + error.message);
    }
});

// URL Check
document.getElementById('urlForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = document.getElementById('urlInput').value;
    
    showLoading('urlLoading');
    document.getElementById('urlResults').classList.remove('show');
    
    try {
        const result = await apiCall('/api/phishing/url', { url });
        hideLoading('urlLoading');
        showResults('urlResults', result, 'url');
    } catch (error) {
        hideLoading('urlLoading');
        alert('Error al analizar la URL: ' + error.message);
    }
});

// Email Check
document.getElementById('emailForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('emailInput').value;
    
    showLoading('emailLoading');
    document.getElementById('emailResults').classList.remove('show');
    
    try {
        const result = await apiCall('/api/phishing/email', { email });
        hideLoading('emailLoading');
        showResults('emailResults', result, 'email');
    } catch (error) {
        hideLoading('emailLoading');
        alert('Error al analizar el email: ' + error.message);
    }
});

// Domain Phishing Check
document.getElementById('domainPhishingForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const domain = document.getElementById('domainPhishingInput').value;
    
    showLoading('domainPhishingLoading');
    document.getElementById('domainPhishingResults').classList.remove('show');
    
    try {
        const result = await apiCall('/api/phishing/domain', { domain });
        hideLoading('domainPhishingLoading');
        showResults('domainPhishingResults', result, 'domain');
    } catch (error) {
        hideLoading('domainPhishingLoading');
        alert('Error al analizar el dominio: ' + error.message);
    }
});

// WHOIS Lookup
document.getElementById('whoisForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const domain = document.getElementById('whoisInput').value;
    
    showLoading('whoisLoading');
    document.getElementById('whoisResults').classList.remove('show');
    
    try {
        const result = await apiCall('/api/domain/whois', { domain });
        hideLoading('whoisLoading');
        showResults('whoisResults', result, 'whois');
    } catch (error) {
        hideLoading('whoisLoading');
        alert('Error al consultar WHOIS: ' + error.message);
    }
});

// Project Analysis
document.getElementById('projectForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = document.getElementById('projectName').value;
    const website = document.getElementById('projectWebsite').value;
    const github = document.getElementById('projectGithub').value;
    
    showLoading('projectLoading');
    document.getElementById('projectResults').classList.remove('show');
    
    try {
        const result = await apiCall('/api/domain/project', { name, website, github });
        hideLoading('projectLoading');
        showResults('projectResults', result, 'project');
    } catch (error) {
        hideLoading('projectLoading');
        alert('Error al analizar el proyecto: ' + error.message);
    }
});

// Breach Check
document.getElementById('breachForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('breachEmail').value;
    
    showLoading('breachLoading');
    document.getElementById('breachResults').classList.remove('show');
    
    try {
        const result = await apiCall('/api/breach/check', { email });
        hideLoading('breachLoading');
        showResults('breachResults', result, 'breach');
    } catch (error) {
        hideLoading('breachLoading');
        alert('Error al verificar brechas: ' + error.message);
    }
});