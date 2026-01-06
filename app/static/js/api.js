/**
 * Wrapper na Fetch API do komunikacji z backendem Flask
 *
 * ⭐ ZADANIE DODATKOWE: Pełne zabezpieczenie CSRF
 * Każde żądanie POST/PUT/DELETE automatycznie zawiera X-CSRFToken header
 */

// Helper do pobierania CSRF tokena z meta tagu
function getCSRFToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
}

// Helper do tworzenia headers z CSRF tokenem
function getHeaders(includeJSON = true) {
    const headers = {
        'X-CSRFToken': getCSRFToken()
    };
    if (includeJSON) {
        headers['Content-Type'] = 'application/json';
    }
    return headers;
}

// --- HOSTS (ZABEZPIECZONE CSRF) ---
export async function fetchHosts() {
    const res = await fetch('/api/hosts');
    return await res.json();
}

export async function createHost(data) {
    const res = await fetch('/api/hosts', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify(data)
    });
    if(!res.ok) throw new Error((await res.json()).error);
    return await res.json();
}

export async function updateHost(id, data) {
    const res = await fetch(`/api/hosts/${id}`, {
        method: 'PUT',
        headers: getHeaders(),
        body: JSON.stringify(data)
    });
    if(!res.ok) throw new Error('Błąd edycji hosta');
    return await res.json();
}

export async function removeHost(id) {
    const res = await fetch(`/api/hosts/${id}`, {
        method: 'DELETE',
        headers: getHeaders(false) // Tylko CSRF token, bez Content-Type
    });
    if(!res.ok) throw new Error('Błąd usuwania hosta');
    return await res.json();
}

// --- MONITORING / LOGI ---
export async function checkHostStatus(id, osType) {
    const endpoint = (osType === 'LINUX')
        ? `/api/hosts/${id}/ssh-info`
        : `/api/hosts/${id}/windows-info`;

    const res = await fetch(endpoint);
    if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || `Błąd HTTP ${res.status}`);
    }
    return await res.json();
}

export async function triggerLogFetch(hostId) {
    const res = await fetch(`/api/hosts/${hostId}/logs`, {
        method: 'POST',
        headers: getHeaders(false)
    });
    if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Błąd pobierania logów');
    }
    return await res.json();
}

// --- IP REGISTRY (ZABEZPIECZONE CSRF) ---
export async function fetchIPs() {
    const res = await fetch('/api/ips');
    if (!res.ok) throw new Error('Błąd pobierania IP');
    return await res.json();
}

export async function createIP(data) {
    const res = await fetch('/api/ips', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify(data)
    });
    if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Błąd dodawania IP');
    }
    return await res.json();
}

export async function updateIP(id, data) {
    const res = await fetch(`/api/ips/${id}`, {
        method: 'PUT',
        headers: getHeaders(),
        body: JSON.stringify(data)
    });
    if (!res.ok) throw new Error('Błąd aktualizacji IP');
    return await res.json();
}

export async function removeIP(id) {
    const res = await fetch(`/api/ips/${id}`, {
        method: 'DELETE',
        headers: getHeaders(false)
    });
    if (!res.ok) throw new Error('Błąd usuwania IP');
    return await res.json();
}

// --- ALERTS ---
export async function fetchAlerts(page = 1, perPage = 20) {
    const res = await fetch(`/api/alerts?page=${page}&per_page=${perPage}`);
    if (!res.ok) throw new Error('Błąd pobierania alertów');
    return await res.json();
}

// ⭐ NOWE API: Stats dla wykresu Chart.js
export async function fetchAlertStats() {
    const res = await fetch('/api/alerts/stats');
    if (!res.ok) throw new Error('Błąd pobierania statystyk');
    return await res.json();
}