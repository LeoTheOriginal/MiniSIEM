import { createEl, clearContainer } from './dom.js';
import { fetchHosts, createHost, updateHost, removeHost } from './api.js';
import { fetchIPs, createIP, updateIP, removeIP } from './api.js';

// --- SEKCJA HOSTÓW ---
const hostsContainer = document.getElementById('hostsListAdmin');
const hostForm = document.getElementById('hostForm');

// --- SEKCJA IP ---
const ipContainer = document.getElementById('ipListAdmin');
const ipForm = document.getElementById('ipForm');
const refreshIPsBtn = document.getElementById('refreshIPsBtn');

// --- MODALE ---
let hostModal = null;
let ipModal = null;

export async function initAdmin() {
    // Inicjalizacja Bootstrap Modals
    const hostModalEl = document.getElementById('editHostModal');
    if (hostModalEl) hostModal = new bootstrap.Modal(hostModalEl);

    const ipModalEl = document.getElementById('editIPModal');
    if (ipModalEl) ipModal = new bootstrap.Modal(ipModalEl);

    // Event Listeners - Hosty
    if (hostForm) hostForm.addEventListener('submit', handleAddHost);
    if (document.getElementById('saveHostBtn')) {
        document.getElementById('saveHostBtn').addEventListener('click', handleSaveHost);
    }

    // Event Listeners - IP (ODKOMENTOWANE)
    if (ipForm) ipForm.addEventListener('submit', handleAddIP);
    if (refreshIPsBtn) refreshIPsBtn.addEventListener('click', refreshIPs);
    if (document.getElementById('saveIPBtn')) {
        document.getElementById('saveIPBtn').addEventListener('click', handleSaveIP);
    }

    if (ipContainer) await refreshIPs();

    // Start Hosty
    if (hostsContainer) await refreshHosts();
}

// ======================= LOGIKA HOSTÓW (GOTOWA) =======================

async function refreshHosts() {
    clearContainer(hostsContainer);
    try {
        const hosts = await fetchHosts();
        hosts.forEach(renderHostRow);
    } catch(e) { console.error(e); }
}

function renderHostRow(host) {
    // 1. Kontener wiersza
    const item = createEl('div', ['list-group-item', 'd-flex', 'justify-content-between', 'align-items-center'], '', hostsContainer);

    // 2. Logika wyboru ikony i koloru
    const iconClass = host.os_type === 'LINUX' ? 'fab fa-linux' : 'fab fa-windows';
    const colorClass = host.os_type === 'LINUX' ? 'text-warning' : 'text-primary';

    // 3. Lewa strona (Ikona + Nazwa + IP) - wstrzykujemy jako HTML dla lepszego wyglądu
    const infoDiv = document.createElement('div');
    infoDiv.className = 'd-flex align-items-center';
    infoDiv.innerHTML = `
        <div class="me-3" style="width: 30px; text-align: center;">
            <i class="${iconClass} ${colorClass} fa-2x"></i>
        </div>
        <div>
            <h6 class="mb-0 fw-bold">${host.hostname}</h6>
            <small class="font-monospace text-muted">
                <i class="fas fa-network-wired me-1"></i>${host.ip_address}
            </small>
        </div>
    `;
    item.appendChild(infoDiv);

    // 4. Prawa strona (Przyciski) - zachowujemy Event Listenery!
    const btnGroup = createEl('div', ['btn-group', 'btn-group-sm'], '', item);

    // Przycisk Edycji
    const editBtn = createEl('button', ['btn', 'btn-outline-secondary'], '', btnGroup);
    editBtn.innerHTML = '<i class="fas fa-edit"></i>'; // Ikona ołówka zamiast emoji
    editBtn.addEventListener('click', () => openHostModal(host));

    // Przycisk Usuwania
    const delBtn = createEl('button', ['btn', 'btn-outline-danger'], '', btnGroup);
    delBtn.innerHTML = '<i class="fas fa-trash-alt"></i>'; // Ikona kosza zamiast emoji
    delBtn.addEventListener('click', async () => {
        if(confirm(`Usunąć hosta ${host.hostname}?`)) {
            await removeHost(host.id);
            await refreshHosts();
        }
    });
}

async function handleAddHost(e) {
    e.preventDefault();
    const data = {
        hostname: document.getElementById('hostName').value,
        ip_address: document.getElementById('hostIP').value,
        os_type: document.getElementById('hostOS').value
    };
    try {
        await createHost(data);
        e.target.reset();
        await refreshHosts();
    } catch(err) { alert(err.message); }
}

function openHostModal(host) {
    document.getElementById('editHostId').value = host.id;
    document.getElementById('editHostName').value = host.hostname;
    document.getElementById('editHostIP').value = host.ip_address;
    document.getElementById('editHostOS').value = host.os_type;
    hostModal.show();
}

async function handleSaveHost() {
    const id = document.getElementById('editHostId').value;
    const data = {
        hostname: document.getElementById('editHostName').value,
        ip_address: document.getElementById('editHostIP').value,
        os_type: document.getElementById('editHostOS').value
    };
    try {
        await updateHost(id, data);
        hostModal.hide();
        await refreshHosts();
    } catch(err) { alert(err.message); }
}


// ======================= LOGIKA IP REGISTRY (ODBLOKOWANE) =======================

async function refreshIPs() {
    clearContainer(ipContainer);
    try {
        const ips = await fetchIPs();
        if(ips.length === 0) createEl('div', ['p-2', 'text-muted', 'small'], 'Pusto.', ipContainer);
        ips.forEach(renderIPRow);
    } catch(e) { console.error("Błąd IP:", e); }
}

function renderIPRow(ip) {
    const item = createEl('div', ['list-group-item', 'd-flex', 'justify-content-between', 'align-items-center'], '', ipContainer);

    const info = createEl('div', [], '', item);
    let color = 'bg-secondary';
    if(ip.status === 'TRUSTED') color = 'bg-success';
    if(ip.status === 'BANNED') color = 'bg-danger';
    createEl('span', ['badge', color, 'me-2'], ip.status[0], info);

    createEl('span', ['fw-bold', 'font-monospace', 'me-2'], ip.ip_address, info);

    let timeStr = '-';
    if (ip.last_seen && ip.last_seen !== '-') {
        const utcDate = new Date(ip.last_seen.replace(" ", "T") + "Z");
        timeStr = utcDate.toLocaleString();
    }
    createEl('small', ['text-muted'], timeStr, info);

    const btnGroup = createEl('div', ['btn-group', 'btn-group-sm'], '', item);

    const editBtn = createEl('button', ['btn', 'btn-outline-secondary'], '✏️', btnGroup);
    editBtn.addEventListener('click', () => openIPModal(ip));

    const delBtn = createEl('button', ['btn', 'btn-outline-danger'], '🗑️', btnGroup);
    delBtn.addEventListener('click', async () => {
        if(confirm(`Usunąć adres IP ${ip.ip_address} z rejestru?`)) {
            try {
                await removeIP(ip.id);
                await refreshIPs();
            } catch (err) { alert("Błąd usuwania: " + err.message); }
        }
    });
}

async function handleAddIP(e) {
    e.preventDefault();
    const data = {
        ip_address: document.getElementById('regIP').value,
        status: document.getElementById('regStatus').value
    };
    try {
        await createIP(data);
        e.target.reset();
        await refreshIPs();
    } catch(err) { alert(err.message); }
}

function openIPModal(ip) {
    document.getElementById('editIPId').value = ip.id;
    document.getElementById('editIPVal').value = ip.ip_address;
    document.getElementById('editIPStatus').value = ip.status;
    ipModal.show();
}

async function handleSaveIP() {
    const id = document.getElementById('editIPId').value;
    const data = {
        ip_address: document.getElementById('editIPVal').value,
        status: document.getElementById('editIPStatus').value
    };
    try {
        await updateIP(id, data);
        ipModal.hide();
        await refreshIPs();
    } catch(err) { alert(err.message); }
}