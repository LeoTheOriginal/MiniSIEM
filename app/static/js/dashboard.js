import { createEl, clearContainer } from './dom.js';
import { fetchHosts, checkHostStatus, triggerLogFetch, fetchAlerts, fetchAlertStats } from './api.js';

const hostsContainer = document.getElementById('hostsContainer');
const alertsBody = document.getElementById('alertsBody');
const alertCount = document.getElementById('alertCount');

// ⭐ Chart.js instances
let hourlyChart = null;
let topIPsChart = null;

export async function initDashboard() {
    if (!hostsContainer) return;

    await refreshHostsList();

    if (alertsBody) {
        await refreshAlertsTable();
    }

    // ⭐ ZADANIE DODATKOWE: Inicjalizacja wykresów
    await initCharts();
}

async function refreshHostsList() {
    clearContainer(hostsContainer);
    try {
        const hosts = await fetchHosts();
        if (hosts.length === 0) {
            const col = createEl('div', ['col-12'], '', hostsContainer);
            const emptyCard = createEl('div', ['card', 'shadow-sm', 'text-center', 'py-5'], '', col);
            const body = createEl('div', ['card-body'], '', emptyCard);
            createEl('i', ['fas', 'fa-server', 'fa-3x', 'text-muted', 'mb-3'], '', body);
            createEl('p', ['text-muted'], 'Brak hostów. Skonfiguruj system w panelu admina.', body);
            return;
        }

        // Renderuj hosty
        hosts.forEach(renderHostCard);

        // Auto-load statusów po 500ms (żeby karty się załadowały)
        setTimeout(() => {
            hosts.forEach((host, index) => {
                setTimeout(() => autoLoadStatus(host), index * 1000);
            });
        }, 500);

    } catch (err) {
        console.error(err);
        const col = createEl('div', ['col-12'], '', hostsContainer);
        createEl('div', ['alert', 'alert-danger'], '❌ Błąd API Hostów: ' + err.message, col);
    }
}

async function autoLoadStatus(host) {
    const hostCard = document.querySelector(`[data-host-id="${host.id}"]`);
    if (!hostCard) return;

    const metricsContainer = hostCard.querySelector('.metrics-container');
    const statusBtn = hostCard.querySelector('.btn-status');

    if (!metricsContainer || !statusBtn) return;

    clearContainer(metricsContainer);
    createEl('div', ['text-center', 'text-muted', 'small', 'py-2'], '🔄 Sprawdzanie dostępności...', metricsContainer);

    try {
        const data = await checkHostStatus(host.id, host.os_type);
        clearContainer(metricsContainer);
        renderMetrics(metricsContainer, data);

        // Update button
        statusBtn.innerHTML = '<i class="fas fa-sync-alt me-1"></i>Odśwież';
        statusBtn.classList.add('btn-success');
        statusBtn.classList.remove('btn-outline-primary');

    } catch (err) {
        clearContainer(metricsContainer);
        const alertDiv = createEl('div', ['alert', 'alert-danger', 'mb-0', 'py-2', 'px-3'], '', metricsContainer);
        alertDiv.innerHTML = '<i class="fas fa-exclamation-triangle me-2"></i><strong>Host niedostępny</strong><br><small>Maszyna może być wyłączona lub nieosiągalna</small>';

        statusBtn.innerHTML = '<i class="fas fa-power-off me-1"></i>Offline';
        statusBtn.classList.add('btn-danger');
        statusBtn.classList.remove('btn-outline-primary');
    }
}

function renderHostCard(host) {
    const col = createEl('div', ['col-md-6', 'col-lg-4'], '', hostsContainer);
    col.style.animationDelay = '0.1s';

    const osClass = host.os_type === 'LINUX' ? 'os-linux' : 'os-windows';
    const card = createEl('div', ['card', 'shadow-sm', 'h-100', 'host-card', osClass], '', col);
    card.setAttribute('data-host-id', host.id);

    const header = createEl('div', ['card-header', 'bg-transparent', 'border-0', 'd-flex', 'justify-content-between', 'align-items-center'], '', card);

    const leftSide = createEl('div', ['d-flex', 'align-items-center'], '', header);
    const icon = host.os_type === 'LINUX' ? 'fa-linux' : 'fa-windows';
    const iconColor = host.os_type === 'LINUX' ? 'text-warning' : 'text-primary';
    createEl('i', ['fab', icon, 'host-icon', iconColor, 'me-2'], '', leftSide);
    const nameDiv = createEl('div', [], '', leftSide);
    createEl('div', ['fw-bold', 'fs-6'], host.hostname, nameDiv);
    createEl('small', ['text-muted', 'font-monospace'], host.ip_address, nameDiv);

    const badge = createEl('span', ['badge', 'badge-os'], host.os_type, header);
    if (host.os_type === 'LINUX') {
        badge.classList.add('bg-warning', 'text-dark');
    } else {
        badge.classList.add('bg-primary');
    }

    const body = createEl('div', ['card-body'], '', card);
    const metricsContainer = createEl('div', ['metrics-container', 'mb-3'], '', body);
    createEl('div', ['text-center', 'text-muted', 'small', 'py-3'], '📊 Ładowanie statusu...', metricsContainer);

    const footer = createEl('div', ['card-footer', 'bg-transparent', 'border-top'], '', card);
    const btnGroup = createEl('div', ['d-grid', 'gap-2'], '', footer);

    const statusBtn = createEl('button', ['btn', 'btn-outline-primary', 'btn-sm', 'btn-status'], '', btnGroup);
    statusBtn.innerHTML = '<i class="fas fa-heartbeat me-1"></i>Sprawdź Status';
    statusBtn.style.cursor = 'pointer';
    statusBtn.style.pointerEvents = 'auto';
    statusBtn.addEventListener('click', function(e) {
        e.preventDefault();
        e.stopPropagation();
        handleCheckStatus(host, metricsContainer, statusBtn);
    }, true);

    const logsBtn = createEl('button', ['btn', 'btn-outline-secondary', 'btn-sm', 'btn-logs'], '', btnGroup);
    logsBtn.innerHTML = '<i class="fas fa-file-alt me-1"></i>Pobierz Logi';
    logsBtn.title = "Pobierz i przeanalizuj logi (SIEM)";
    logsBtn.style.cursor = 'pointer';
    logsBtn.style.pointerEvents = 'auto';
    logsBtn.addEventListener('click', function(e) {
        e.preventDefault();
        e.stopPropagation();
        handleFetchLogs(host, logsBtn);
    }, true);
}

async function handleCheckStatus(host, container, btn) {
    if (btn.disabled) return;

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Sprawdzanie...';

    clearContainer(container);
    createEl('div', ['text-center', 'text-muted', 'small', 'py-2'], '🔄 Łączenie z hostem...', container);

    try {
        const data = await checkHostStatus(host.id, host.os_type);
        clearContainer(container);
        renderMetrics(container, data);

        btn.innerHTML = '<i class="fas fa-sync-alt me-1"></i>Odśwież';
        btn.classList.remove('btn-outline-primary', 'btn-danger');
        btn.classList.add('btn-success');

        setTimeout(() => {
            btn.classList.remove('btn-success');
            btn.classList.add('btn-outline-primary');
        }, 2000);

    } catch (err) {
        clearContainer(container);
        const alertDiv = createEl('div', ['alert', 'alert-danger', 'mb-0', 'py-2', 'px-3'], '', container);
        alertDiv.innerHTML = '<i class="fas fa-exclamation-triangle me-2"></i><strong>Host niedostępny</strong><br><small>Maszyna może być wyłączona lub nieosiągalna</small>';

        btn.innerHTML = '<i class="fas fa-power-off me-1"></i>Offline';
        btn.classList.remove('btn-outline-primary', 'btn-success');
        btn.classList.add('btn-danger');
    } finally {
        btn.disabled = false;
    }
}

function renderMetrics(container, data) {
    const ramItem = createEl('div', ['metric-item', 'd-flex', 'justify-content-between', 'align-items-center'], '', container);
    const ramLabel = createEl('span', ['metric-label'], '', ramItem);
    ramLabel.innerHTML = '<i class="fas fa-memory text-primary me-1"></i>RAM';
    createEl('span', ['metric-value'], `${data.free_ram_mb} MB`, ramItem);

    const hddItem = createEl('div', ['metric-item', 'd-flex', 'justify-content-between', 'align-items-center'], '', container);
    const hddLabel = createEl('span', ['metric-label'], '', hddItem);
    hddLabel.innerHTML = '<i class="fas fa-hdd text-warning me-1"></i>HDD';
    createEl('span', ['metric-value'], data.disk_info, hddItem);

    const hddPercent = parseFloat(data.disk_info);
    if (!isNaN(hddPercent)) {
        const progressDiv = createEl('div', ['progress', 'mt-1', 'w-100'], '', container);
        progressDiv.style.height = '6px';
        const progressBar = createEl('div', ['progress-bar'], '', progressDiv);
        progressBar.style.width = hddPercent + '%';
        if (hddPercent > 80) progressBar.classList.add('bg-danger');
        else if (hddPercent > 60) progressBar.classList.add('bg-warning');
        else progressBar.classList.add('bg-success');
    }

    const cpuItem = createEl('div', ['metric-item', 'd-flex', 'justify-content-between', 'align-items-center'], '', container);
    const cpuLabel = createEl('span', ['metric-label'], '', cpuItem);
    cpuLabel.innerHTML = '<i class="fas fa-microchip text-info me-1"></i>CPU';
    createEl('span', ['metric-value'], data.cpu_load, cpuItem);

    const uptimeItem = createEl('div', ['metric-item', 'd-flex', 'justify-content-between', 'align-items-center'], '', container);
    const uptimeLabel = createEl('span', ['metric-label'], '', uptimeItem);
    uptimeLabel.innerHTML = '<i class="fas fa-clock text-secondary me-1"></i>Uptime';
    createEl('span', ['metric-value'], data.uptime_hours, uptimeItem);
}

async function handleFetchLogs(host, btn) {
    if (btn.disabled) return;

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Analizuję...';

    try {
        const result = await triggerLogFetch(host.id);

        if (result.alerts_generated > 0) {
            btn.innerHTML = `<i class="fas fa-exclamation-triangle me-1"></i>${result.alerts_generated} alertów`;
            btn.classList.remove('btn-outline-secondary');
            btn.classList.add('btn-danger');
        } else {
            btn.innerHTML = '<i class="fas fa-check-circle me-1"></i>Brak zagrożeń';
            btn.classList.remove('btn-outline-secondary');
            btn.classList.add('btn-success');
        }

        setTimeout(() => {
            btn.innerHTML = '<i class="fas fa-file-alt me-1"></i>Pobierz Logi';
            btn.classList.remove('btn-danger', 'btn-success');
            btn.classList.add('btn-outline-secondary');
            btn.disabled = false;
        }, 3000);

        // ⭐ Odśwież ZARÓWNO tabelę alertów JAK I wykresy po pobraniu logów
        await refreshAlertsTable();
        await updateCharts();

    } catch (err) {
        alert("❌ Błąd pobierania logów: " + err.message);
        btn.innerHTML = '<i class="fas fa-file-alt me-1"></i>Pobierz Logi';
        btn.classList.remove('btn-danger', 'btn-success');
        btn.classList.add('btn-outline-secondary');
        btn.disabled = false;
    }
}

let currentPage = 1;
const perPage = 20;

async function refreshAlertsTable(page = 1) {
    if (!alertsBody) return;
    clearContainer(alertsBody);

    try {
        const data = await fetchAlerts(page, perPage);

        const alerts = data.alerts;

        if (alerts.length === 0) {
            const row = createEl('tr', [], '', alertsBody);
            const cell = createEl('td', ['text-center', 'text-muted', 'py-4'], '', row);
            cell.innerHTML = '<i class="fas fa-check-circle fa-2x mb-2 d-block text-success"></i>Brak wykrytych zagrożeń';
            cell.colSpan = 6;

            if (alertCount) {
                alertCount.textContent = '0';
            }

            // Ukryj pagination jeśli brak alertów
            const paginationContainer = document.getElementById('alertsPagination');
            if (paginationContainer) {
                clearContainer(paginationContainer);
            }

            return;
        }

        // Pokaż CAŁKOWITĄ liczbę alertów (nie tylko na stronie)
        if (alertCount) {
            alertCount.textContent = data.total;
        }

        // Renderuj alerty
        alerts.forEach(alert => {
            const row = createEl('tr', [], '', alertsBody);

            const utcDate = new Date(alert.timestamp.replace(" ", "T") + "Z");
            createEl('td', ['small'], utcDate.toLocaleString('pl-PL', { timeZone: 'UTC' }), row);

            const hostCell = createEl('td', [], '', row);
            hostCell.innerHTML = `<i class="fas fa-server me-1 text-muted"></i><span class="fw-bold">${alert.host_name}</span>`;

            createEl('td', ['font-monospace', 'small'], alert.alert_type, row);

            const ipCell = createEl('td', ['font-monospace', 'small'], '', row);
            ipCell.innerHTML = `<i class="fas fa-network-wired me-1 text-muted"></i>${alert.source_ip || '-'}`;

            createEl('td', ['small'], alert.message, row);

            const badgeCell = createEl('td', ['text-center'], '', row);
            const badge = createEl('span', ['badge', 'badge-severity'], alert.severity, badgeCell);

            if (alert.severity === 'CRITICAL') {
                badge.classList.add('badge-critical');
            } else if (alert.severity === 'WARNING') {
                badge.classList.add('badge-warning');
            } else {
                badge.classList.add('badge-info');
            }
        });

        // Renderuj kontrolki paginacji
        renderPagination(data);

        currentPage = page;

    } catch (err) {
        console.error("Błąd tabeli alertów:", err);
        const row = createEl('tr', [], '', alertsBody);
        const cell = createEl('td', ['text-center', 'text-danger', 'py-4'], '', row);
        cell.innerHTML = `<i class="fas fa-exclamation-triangle fa-2x mb-2 d-block"></i>Błąd pobierania alertów: ${err.message}`;
        cell.colSpan = 6;
    }
}

function renderPagination(data) {
    const paginationContainer = document.getElementById('alertsPagination');
    if (!paginationContainer) return;

    clearContainer(paginationContainer);

    // Jeśli tylko jedna strona, nie pokazuj paginacji
    if (data.pages <= 1) return;

    const nav = createEl('nav', ['mt-3'], '', paginationContainer);
    const ul = createEl('ul', ['pagination', 'pagination-sm', 'justify-content-center', 'mb-0'], '', nav);

    // Przycisk "Poprzednia"
    const prevLi = createEl('li', ['page-item'], '', ul);
    if (!data.has_prev) prevLi.classList.add('disabled');
    const prevLink = createEl('a', ['page-link'], '', prevLi);
    prevLink.href = '#alerts';
    prevLink.innerHTML = '<i class="fas fa-chevron-left"></i> Poprzednia';
    if (data.has_prev) {
        prevLink.addEventListener('click', (e) => {
            e.preventDefault();
            refreshAlertsTable(data.page - 1);
            document.getElementById('alertsTable').scrollIntoView({ behavior: 'smooth' });
        });
    }

    // Numerki stron (pokazujemy max 7 przycisków)
    let startPage = Math.max(1, data.page - 3);
    let endPage = Math.min(data.pages, data.page + 3);

    // Zawsze pokazuj pierwszą stronę
    if (startPage > 1) {
        createPageButton(ul, 1, data.page);
        if (startPage > 2) {
            const dotsLi = createEl('li', ['page-item', 'disabled'], '', ul);
            createEl('span', ['page-link'], '...', dotsLi);
        }
    }

    // Środkowe strony
    for (let i = startPage; i <= endPage; i++) {
        createPageButton(ul, i, data.page);
    }

    // Zawsze pokazuj ostatnią stronę
    if (endPage < data.pages) {
        if (endPage < data.pages - 1) {
            const dotsLi = createEl('li', ['page-item', 'disabled'], '', ul);
            createEl('span', ['page-link'], '...', dotsLi);
        }
        createPageButton(ul, data.pages, data.page);
    }

    // Przycisk "Następna"
    const nextLi = createEl('li', ['page-item'], '', ul);
    if (!data.has_next) nextLi.classList.add('disabled');
    const nextLink = createEl('a', ['page-link'], '', nextLi);
    nextLink.href = '#alerts';
    nextLink.innerHTML = 'Następna <i class="fas fa-chevron-right"></i>';
    if (data.has_next) {
        nextLink.addEventListener('click', (e) => {
            e.preventDefault();
            refreshAlertsTable(data.page + 1);
            document.getElementById('alertsTable').scrollIntoView({ behavior: 'smooth' });
        });
    }

    // Info o stronie
    const infoDiv = createEl('div', ['text-center', 'text-muted', 'small', 'mt-2'], '', paginationContainer);
    infoDiv.innerHTML = `Strona ${data.page} z ${data.pages} | Wszystkich alertów: <strong>${data.total}</strong>`;
}

function createPageButton(ul, pageNum, currentPage) {
    const pageLi = createEl('li', ['page-item'], '', ul);
    if (pageNum === currentPage) {
        pageLi.classList.add('active');
    }
    const pageLink = createEl('a', ['page-link'], pageNum.toString(), pageLi);
    pageLink.href = '#alerts';
    pageLink.addEventListener('click', (e) => {
        e.preventDefault();
        refreshAlertsTable(pageNum);
        document.getElementById('alertsTable').scrollIntoView({ behavior: 'smooth' });
    });
}

// ===================================================================
// ⭐ ZADANIE DODATKOWE: Wykresy Chart.js
// ===================================================================

async function initCharts() {
    const hourlyCanvas = document.getElementById('hourlyChart');
    const topIPsCanvas = document.getElementById('topIPsChart');

    if (!hourlyCanvas || !topIPsCanvas) {
        console.log("Chart canvas not found, skipping chart initialization");
        return;
    }

    try {
        const stats = await fetchAlertStats();

        // Wykres alertów na godzinę (liniowy)
        hourlyChart = new Chart(hourlyCanvas, {
            type: 'line',
            data: {
                labels: stats.hourly.labels,
                datasets: [{
                    label: 'Liczba Alertów',
                    data: stats.hourly.data,
                    borderColor: 'rgb(255, 99, 132)',
                    backgroundColor: 'rgba(255, 99, 132, 0.2)',
                    tension: 0.3,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        display: false
                    },
                    title: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                }
            }
        });

        // Wykres Top 5 IP (poziomy słupkowy)
        topIPsChart = new Chart(topIPsCanvas, {
            type: 'bar',
            data: {
                labels: stats.top_ips.labels.length > 0 ? stats.top_ips.labels : ['Brak danych'],
                datasets: [{
                    label: 'Liczba Ataków',
                    data: stats.top_ips.data.length > 0 ? stats.top_ips.data : [0],
                    backgroundColor: [
                        'rgba(255, 99, 132, 0.8)',
                        'rgba(255, 159, 64, 0.8)',
                        'rgba(255, 205, 86, 0.8)',
                        'rgba(75, 192, 192, 0.8)',
                        'rgba(54, 162, 235, 0.8)'
                    ],
                    borderColor: [
                        'rgb(255, 99, 132)',
                        'rgb(255, 159, 64)',
                        'rgb(255, 205, 86)',
                        'rgb(75, 192, 192)',
                        'rgb(54, 162, 235)'
                    ],
                    borderWidth: 2
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                }
            }
        });

    } catch (err) {
        console.error("Error initializing charts:", err);
    }
}

async function updateCharts() {
    if (!hourlyChart || !topIPsChart) {
        // Jeśli wykresy nie były jeszcze zainicjalizowane, zrób to teraz
        await initCharts();
        return;
    }

    try {
        const stats = await fetchAlertStats();

        // Update hourly chart
        hourlyChart.data.labels = stats.hourly.labels;
        hourlyChart.data.datasets[0].data = stats.hourly.data;
        hourlyChart.update();

        // Update top IPs chart
        topIPsChart.data.labels = stats.top_ips.labels.length > 0 ? stats.top_ips.labels : ['Brak danych'];
        topIPsChart.data.datasets[0].data = stats.top_ips.data.length > 0 ? stats.top_ips.data : [0];
        topIPsChart.update();

    } catch (err) {
        console.error("Error updating charts:", err);
    }
}