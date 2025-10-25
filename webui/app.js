const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

const SAFE_TUNING_CHARS = new Set('0123456789abcx'.split(''));
const ALLOWED_FORMATS = new Set(['html', 'csv', 'txt', 'xml']);
const ACTIVE_STATUSES = new Set(['running', 'paused']);
const MAX_LOG_LINES = 1000;
const REPORT_NAME_PATTERN = /^[A-Za-z0-9._-]+\.(html|csv|txt|xml)$/;

const app = express();

app.use(session({
    secret: process.env.SESSION_SECRET || 'very-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

const outputDir = process.env.CYBERSEC_OUTPUT_DIR || process.env.NIKTO_OUTPUT_DIR || '/scans';
const scannerContainer = process.env.CYBERSEC_CONTAINER || process.env.NIKTO_CONTAINER || 'cybersec_scanner';
const resolvedOutputDir = path.resolve(outputDir);
const rawContainerOutputDir = process.env.CYBERSEC_CONTAINER_OUTPUT_DIR || process.env.NIKTO_CONTAINER_OUTPUT_DIR || '/scans';
const containerOutputDir = normalizeContainerDir(rawContainerOutputDir);


app.set('views', path.join(__dirname, 'views'));
app.engine('html', require('ejs').renderFile);
app.set('view engine', 'html');

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

const scans = Object.create(null);

function normalizeContainerDir(raw) {
    let normalized = (raw || '').trim();
    if (!normalized) {
        return '/scans';
    }
    normalized = normalized.replace(/[\/]+/g, '/');
    if (/^[A-Za-z]:/.test(normalized)) {
        normalized = normalized.slice(2);
    }
    if (!normalized.startsWith('/')) {
        normalized = '/' + normalized;
    }
    normalized = normalized.replace(/[\/]+/g, '/');
    if (normalized === '/') {
        return '/scans';
    }
    return normalized;
}

function sanitizeTarget(rawTarget) {
    const trimmed = (rawTarget || '').trim();
    if (!trimmed) {
        return '';
    }
    return trimmed.replace(/[^a-zA-Z0-9\-._:/]/g, '');
}

function normalizeTuning(rawValue) {
    if (!rawValue) {
        return '';
    }
    const chars = Array.from(String(rawValue).toLowerCase());
    const unique = [];
    for (const ch of chars) {
        if (SAFE_TUNING_CHARS.has(ch) && !unique.includes(ch)) {
            unique.push(ch);
        }
    }
    return unique.join('');
}

function validatePort(rawPort) {
    if (!rawPort && rawPort !== 0) {
        return '';
    }
    const trimmed = String(rawPort).trim();
    if (trimmed === '') {
        return '';
    }
    const value = Number.parseInt(trimmed, 10);
    if (!Number.isInteger(value) || value < 1 || value > 65535) {
        return null;
    }
    return value.toString();
}

function sanitizeScanId(rawScanId) {
    const normalized = (rawScanId || '').trim();
    if (!/^\d+$/.test(normalized)) {
        return '';
    }
    return normalized;
}

function sanitizeReportName(rawName) {
    const normalized = (rawName || '').trim();
    if (!REPORT_NAME_PATTERN.test(normalized)) {
        return '';
    }
    return normalized;
}

function sendSse(res, message) {
    const lines = message.split(/\r?\n/);
    lines.forEach(line => {
        res.write(`data: ${line}\n`);
    });
    res.write('\n');
}

function attachClient(entry, res) {
    res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive'
    });
    entry.clients.add(res);
    res.on('close', () => {
        entry.clients.delete(res);
    });
}

function broadcast(entry, message) {
    if (!message) {
        return;
    }
    entry.logs.push(message);
    if (entry.logs.length > MAX_LOG_LINES) {
        entry.logs.shift();
    }
    const clients = Array.from(entry.clients);
    clients.forEach(client => {
        try {
            sendSse(client, message);
        } catch (err) {
            entry.clients.delete(client);
        }
    });
}

function endAllClients(entry) {
    const clients = Array.from(entry.clients);
    entry.clients.clear();
    clients.forEach(client => {
        try {
            client.end();
        } catch (err) {
            // ignore
        }
    });
}

function generateScanId() {
    let candidate = Date.now().toString();
    while (scans[candidate]) {
        candidate = (Number(candidate) + 1).toString();
    }
    return candidate;
}

function handleStreamAttach(req, res, rawScanId) {
    const scanId = sanitizeScanId(rawScanId);
    if (!scanId) {
        return res.status(400).send('Invalid scanId');
    }
    const entry = scans[scanId];
    if (!entry) {
        return res.status(404).send('Scan not found');
    }
    req.session.scanId = scanId;
    attachClient(entry, res);
    entry.logs.forEach(line => {
        sendSse(res, line);
    });
    if (!ACTIVE_STATUSES.has(entry.status)) {
        setImmediate(() => res.end());
    }
}

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/index.html'));
});

app.get('/scan-stream', (req, res) => {
    if (req.query.scanId && !req.query.target) {
        return handleStreamAttach(req, res, req.query.scanId);
    }

    const target = sanitizeTarget(req.query.target);
    if (!target) {
        return res.status(400).send('Target required');
    }

    const format = (req.query.format || 'html').toLowerCase();
    if (!ALLOWED_FORMATS.has(format)) {
        return res.status(400).send('Invalid format');
    }

    const portValue = validatePort(req.query.port);
    if (portValue === null) {
        return res.status(400).send('Invalid port');
    }

    const tuning = normalizeTuning(req.query.tuning);
    const ssl = req.query.ssl === 'true';
    const timestamp = Date.now();
    const safeName = target.replace(/[:/]/g, '_');
    const fileName = `${safeName}_${timestamp}.${format}`;
    const containerOutputPath = path.posix.join(containerOutputDir, fileName);
    const scanId = generateScanId();

    console.log(`[scan] writing report to ${containerOutputPath}`);
    const entry = {
        status: 'running',
        fileName,
        target,
        proc: null,
        logs: [],
        clients: new Set(),
        createdAt: new Date()
    };
    scans[scanId] = entry;
    if (!fs.existsSync(resolvedOutputDir)) {
        fs.mkdirSync(resolvedOutputDir, { recursive: true });
    }
    req.session.scanId = scanId;

    attachClient(entry, res);
    broadcast(entry, `[INFO] Scan ID: ${scanId}`);
    broadcast(entry, `[INFO] Writing report to ${containerOutputPath}`);

    const args = ['exec', scannerContainer, 'nikto.pl', '-h', target];
    if (ssl) {
        args.push('-ssl');
    }
    if (portValue) {
        args.push('-port', portValue);
    }
    if (tuning) {
        args.push('-Tuning', tuning);
    }
    args.push('-Format', format, '-o', containerOutputPath);

    const proc = spawn('docker', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    entry.proc = proc;

    const handleChunk = (prefix, chunk) => {
        chunk.toString().split(/\r?\n/).forEach(line => {
            const trimmed = line.trim();
            if (!trimmed) {
                return;
            }
            broadcast(entry, prefix ? `${prefix} ${trimmed}` : trimmed);
        });
    };

    proc.stdout.on('data', data => handleChunk('', data));
    proc.stderr.on('data', data => handleChunk('[ERR]', data));

    proc.on('error', err => {
        entry.proc = null;
        entry.status = 'failed';
        broadcast(entry, `[ERR] Failed to start scan: ${err.message}`);
        broadcast(entry, '** Scan failed to start **');
        endAllClients(entry);
    });

    proc.on('close', code => {
        entry.proc = null;
        if (entry.status === 'aborted') {
            endAllClients(entry);
            return;
        }
        entry.status = (code === 0 ? 'finished' : 'failed');
        broadcast(entry, `** Scan finished with exit code ${code} **`);
        broadcast(entry, `Report file: /reports/${fileName}`);
        endAllClients(entry);
    });
});

app.get('/scan-status', (req, res) => {
    const scanId = req.session.scanId;
    if (!scanId || !scans[scanId]) {
        return res.json({ scanId: null });
    }
    const info = scans[scanId];
    return res.json({
        scanId,
        status: info.status,
        fileName: info.fileName,
        target: info.target
    });
});

app.post('/scan-stop', (req, res) => {
    const scanId = sanitizeScanId(req.body.scanId);
    if (!scanId) {
        return res.status(400).json({ error: 'Invalid scan ID' });
    }
    const scan = scans[scanId];
    if (!scan) {
        return res.status(404).json({ error: 'Scan ID not found' });
    }
    if (scan.status !== 'running' || !scan.proc) {
        return res.status(400).json({ error: 'Scan is not running' });
    }
    const killed = scan.proc.kill('SIGTERM');
    if (!killed) {
        return res.status(500).json({ error: 'Unable to stop scan' });
    }
    scan.status = 'aborted';
    broadcast(scan, '** Scan aborted by user **');
    return res.json({ status: 'aborted', scanId });
});

app.post('/scan-pause', (req, res) => {
    const scanId = sanitizeScanId(req.body.scanId);
    if (!scanId) {
        return res.status(400).json({ error: 'Invalid scan ID' });
    }
    const scan = scans[scanId];
    if (!scan) {
        return res.status(404).json({ error: 'Scan ID not found' });
    }
    if (!scan.proc) {
        return res.status(400).json({ error: 'Scan process not available' });
    }
    if (scan.status === 'running') {
        const paused = scan.proc.kill('SIGSTOP');
        if (!paused) {
            return res.status(500).json({ error: 'Unable to pause scan' });
        }
        scan.status = 'paused';
        broadcast(scan, '[INFO] Scan paused');
        return res.json({ status: 'paused', scanId });
    }
    if (scan.status === 'paused') {
        const resumed = scan.proc.kill('SIGCONT');
        if (!resumed) {
            return res.status(500).json({ error: 'Unable to resume scan' });
        }
        scan.status = 'running';
        broadcast(scan, '[INFO] Scan resumed');
        return res.json({ status: 'running', scanId });
    }
    return res.status(400).json({ error: 'Cannot pause/resume in current state' });
});

app.get('/history', (req, res) => {
    fs.readdir(resolvedOutputDir, (err, files) => {
        if (err) {
            if (err.code === 'ENOENT') {
                return res.json({ reports: [] });
            }
            console.error('Cannot list reports:', err);
            return res.status(500).json({ error: 'Cannot list reports' });
        }
        const reports = files
            .filter(isReportFileName)
            .sort()
            .reverse();
        res.json({ reports });
    });
});

app.get('/list', (req, res) => {
    fs.readdir(resolvedOutputDir, (err, files) => {
        if (err) {
            if (err.code === 'ENOENT') {
                return res.render('list', { reports: [] });
            }
            console.error('Cannot list reports:', err);
            return res.status(500).send('Unable to list reports');
        }
        const reports = files
            .filter(isReportFileName)
            .sort()
            .reverse();
        res.render('list', { reports });
    });
});

app.get('/reports/:file', (req, res) => {
    const file = sanitizeReportName(req.params.file);
    if (!file) {
        return res.status(400).send('Invalid file name');
    }
    const filePath = path.resolve(resolvedOutputDir, file);
    if (!filePath.startsWith(resolvedOutputDir)) {
        return res.status(400).send('Invalid file location');
    }
    fs.access(filePath, fs.constants.R_OK, err => {
        if (err) {
            return res.status(404).send('Report not found');
        }
        res.sendFile(filePath);
    });
});

const PORT = process.env.PORT || 2609;
app.listen(PORT, () => console.log(`Web UI listening on port ${PORT}`));

function isReportFileName(name) {
    return REPORT_NAME_PATTERN.test(name);
}



