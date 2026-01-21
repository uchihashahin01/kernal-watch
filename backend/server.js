require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const Groq = require('groq-sdk');
const geoip = require('geoip-lite');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

// ============================================
// BINARY HASH DETECTION (Catches renamed tools)
// ============================================
// This detects tools like netcat even if renamed to "update-checker"
const KNOWN_DANGEROUS_HASHES = new Map();  // hash -> {name, threat_level, description}
const BINARY_HASH_CACHE = new Map();       // path -> {hash, timestamp}
const HASH_CACHE_TTL = 60000;              // Cache for 60 seconds

// Function to populate known hashes at startup
async function loadKnownBinaryHashes() {
    const dangerousBinaries = [
        {
            paths: ['/usr/bin/nc', '/bin/nc', '/usr/bin/netcat', '/bin/netcat', '/usr/bin/ncat'],
            name: 'netcat', threat: 'HIGH', desc: 'Network utility often used for reverse shells'
        },
        {
            paths: ['/usr/bin/nmap', '/bin/nmap'],
            name: 'nmap', threat: 'MEDIUM', desc: 'Network scanner for reconnaissance'
        },
        {
            paths: ['/usr/bin/socat', '/bin/socat'],
            name: 'socat', threat: 'HIGH', desc: 'Socket relay tool used for tunneling'
        },
        {
            paths: ['/usr/bin/masscan', '/bin/masscan'],
            name: 'masscan', threat: 'MEDIUM', desc: 'Mass port scanner'
        },
    ];

    console.log('[HASH] Loading known binary signatures...');

    for (const binary of dangerousBinaries) {
        for (const binPath of binary.paths) {
            try {
                if (fs.existsSync(binPath)) {
                    const hash = await computeFileHash(binPath);
                    KNOWN_DANGEROUS_HASHES.set(hash, {
                        originalName: binary.name,
                        threatLevel: binary.threat,
                        description: binary.desc,
                        originalPath: binPath
                    });
                    console.log(`[HASH] Loaded signature for ${binary.name}: ${hash.substring(0, 16)}...`);
                }
            } catch (e) {
                // Binary not found on this system - that's OK
            }
        }
    }

    console.log(`[HASH] Loaded ${KNOWN_DANGEROUS_HASHES.size} dangerous binary signatures`);
}

// Compute SHA-256 hash of a file
function computeFileHash(filePath) {
    return new Promise((resolve, reject) => {
        try {
            const hash = crypto.createHash('sha256');
            const stream = fs.createReadStream(filePath);
            stream.on('data', data => hash.update(data));
            stream.on('end', () => resolve(hash.digest('hex')));
            stream.on('error', reject);
        } catch (e) {
            reject(e);
        }
    });
}

// Check if a binary matches a known dangerous hash
async function checkBinaryHash(filePath) {
    if (!filePath || !filePath.startsWith('/')) return null;

    try {
        // Check cache first
        const cached = BINARY_HASH_CACHE.get(filePath);
        if (cached && (Date.now() - cached.timestamp) < HASH_CACHE_TTL) {
            return KNOWN_DANGEROUS_HASHES.get(cached.hash) || null;
        }

        // Check if file exists and is executable
        if (!fs.existsSync(filePath)) return null;

        const hash = await computeFileHash(filePath);

        // Update cache
        BINARY_HASH_CACHE.set(filePath, { hash, timestamp: Date.now() });

        // Check against known dangerous hashes
        const match = KNOWN_DANGEROUS_HASHES.get(hash);
        if (match) {
            console.log(`[!!!] RENAMED BINARY DETECTED: ${filePath} is actually ${match.originalName}!`);
        }

        return match || null;
    } catch (e) {
        return null;
    }
}

// Initialize hashes at startup
loadKnownBinaryHashes();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST", "DELETE"]
    }
});

// Middleware
app.use(cors());
app.use(express.json());

// ============================================
// DATABASE INITIALIZATION (SQLite)
// ============================================
const DB_PATH = path.join(__dirname, 'kernel-watch.sqlite');
const db = new Database(DB_PATH);

// Enable WAL mode for better concurrent performance
db.pragma('journal_mode = WAL');

// Create tables if they don't exist
db.exec(`
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        type TEXT NOT NULL,
        severity TEXT NOT NULL,
        process_name TEXT,
        pid INTEGER,
        details TEXT,
        ai_analysis TEXT
    );

    CREATE TABLE IF NOT EXISTS whitelist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        process_name TEXT UNIQUE NOT NULL,
        added_at TEXT NOT NULL,
        reason TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
    CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);
    CREATE INDEX IF NOT EXISTS idx_whitelist_process ON whitelist(process_name);
`);

console.log('[DB] SQLite database initialized at:', DB_PATH);

// Prepared statements for performance
const insertEventStmt = db.prepare(`
    INSERT INTO events (timestamp, type, severity, process_name, pid, details, ai_analysis)
    VALUES (?, ?, ?, ?, ?, ?, ?)
`);

const insertWhitelistStmt = db.prepare(`
    INSERT OR IGNORE INTO whitelist (process_name, added_at, reason)
    VALUES (?, ?, ?)
`);

const getWhitelistStmt = db.prepare(`SELECT process_name FROM whitelist`);

// Load dynamic whitelist into memory for fast lookups
let dynamicWhitelist = new Set(
    getWhitelistStmt.all().map(row => row.process_name)
);

console.log('[DB] Loaded', dynamicWhitelist.size, 'entries from dynamic whitelist');

// ============================================
// Groq Client
// ============================================
let groq;
try {
    groq = new Groq({
        apiKey: process.env.GROQ_API_KEY
    });
    console.log('[GROQ] API Key loaded:', process.env.GROQ_API_KEY ? 'Yes (length: ' + process.env.GROQ_API_KEY.length + ')' : 'No');
} catch (e) {
    console.error('[GROQ] Failed to initialize:', e.message);
}

// ============================================
// STATIC WHITELISTING (hardcoded)
// ============================================
const STATIC_WHITELISTED_PROCESSES = [
    'cpuUsage.sh', 'sed', 'cat', 'sleep', 'head', 'tail', 'grep', 'cut',
    'xfce4-panel-gen', 'wrapper-2.0', 'genmon-vpnip.sh', 'ip',
    'which', 'ps', 'antigravity', 'sh', 'bash',
    'node', 'npm', 'vite', 'esbuild'
];

const WHITELISTED_PATHS = [
    '/usr/share/kali-themes/',
    '/usr/share/antigravity/',
    '/usr/bin/cat', '/usr/bin/sed', '/usr/bin/grep', '/usr/bin/cut',
    '/usr/bin/head', '/usr/bin/tail', '/usr/bin/sleep', '/usr/bin/which',
    '/usr/bin/ps', '/usr/sbin/ip'
];

function isWhitelisted(event) {
    // CRITICAL: Never whitelist events that eBPF already marked as threats
    // This ensures blocked processes (like reverse shells) still appear on dashboard
    if (event.threat_level && event.threat_level >= 2) {
        return false;
    }

    // Check static whitelist (command name)
    if (event.comm && STATIC_WHITELISTED_PROCESSES.includes(event.comm)) return true;

    // Check DYNAMIC whitelist from database
    if (event.comm && dynamicWhitelist.has(event.comm)) {
        return true;
    }

    // Check path-based whitelist
    if (event.fname) {
        // Check dynamic whitelist by path
        if (dynamicWhitelist.has(event.fname)) return true;

        for (const path of WHITELISTED_PATHS) {
            if (event.fname.startsWith(path) || event.fname === path) return true;
        }
    }
    return false;
}

// Suspicious command patterns
const SUSPICIOUS_PATHS = ['/tmp/', '/var/tmp/', '/dev/shm/'];
const SUSPICIOUS_BINARIES = ['nc', 'ncat', 'netcat', 'socat', 'curl', 'wget', 'nmap', 'masscan'];
const SUSPICIOUS_PATTERNS = ['/dev/tcp', 'bash -i', 'python -c', 'perl -e', 'ruby -e', 'php -r', 'base64'];

// Network services that should NOT spawn shells (lineage check)
const NETWORK_SERVICES = ['node', 'nginx', 'apache', 'apache2', 'php', 'php-fpm', 'python', 'python3', 'ruby', 'perl', 'java'];
const SHELLS = ['bash', 'sh', 'zsh', 'dash', 'fish', 'ksh'];

function isSuspicious(event) {
    // CRITICAL: Already flagged by eBPF
    if (event.threat_level && event.threat_level > 0) return true;

    // MASTER LEVEL: Fileless malware detection
    if (event.type === 'MEMFD') {
        console.log(`[!!!] FILELESS MALWARE: memfd_create by ${event.comm}`);
        return true;
    }

    // MASTER LEVEL: Process lineage - shell from network service
    if (event.parent_comm && event.comm) {
        if (NETWORK_SERVICES.includes(event.parent_comm) && SHELLS.includes(event.comm)) {
            console.log(`[!!!] REVERSE SHELL: ${event.parent_comm} → ${event.comm}`);
            return true;
        }
    }

    // Path-based detection
    if (event.fname) {
        for (const path of SUSPICIOUS_PATHS) {
            if (event.fname.startsWith(path)) return true;
        }
        const basename = event.fname.split('/').pop();
        if (SUSPICIOUS_BINARIES.includes(basename)) return true;
        for (const pattern of SUSPICIOUS_PATTERNS) {
            if (event.fname.includes(pattern)) return true;
        }
    }

    if (event.comm && SUSPICIOUS_BINARIES.includes(event.comm)) return true;
    return false;
}

// ============================================
// Helper: Get severity string from threat level
// ============================================
function getSeverity(event) {
    if (event.threat_level >= 2) return 'critical';
    if (event.threat_level >= 1) return 'suspicious';
    if (event.ai_analysis && event.ai_analysis.risk_score >= 7) return 'critical';
    if (event.ai_analysis && event.ai_analysis.risk_score >= 4) return 'suspicious';
    if (event.is_threat) return 'suspicious';
    return 'safe';
}

// ============================================
// In-Memory Buffers (for real-time dashboard)
// ============================================
const threatLog = [];
const MAX_THREAT_LOG = 100;

function addToThreatLog(event) {
    threatLog.unshift({
        ...event,
        logged_at: new Date().toISOString()
    });
    if (threatLog.length > MAX_THREAT_LOG) {
        threatLog.pop();
    }
}

// AI Queue
const aiQueue = [];
let aiProcessing = false;

const aiHistoryLog = [];
const MAX_AI_HISTORY = 50;

function addToAIHistory(event, analysis) {
    aiHistoryLog.unshift({
        id: Date.now(),
        pid: event.pid,
        comm: event.comm,
        type: event.type,
        fname: event.fname,
        risk_score: analysis.risk_score,
        verdict: analysis.verdict,
        analysis: analysis.analysis,
        attack_technique: analysis.attack_technique,
        recommendation: analysis.recommendation,
        timestamp: new Date().toISOString()
    });
    if (aiHistoryLog.length > MAX_AI_HISTORY) {
        aiHistoryLog.pop();
    }
}

async function processAIQueue() {
    if (aiProcessing || aiQueue.length === 0) return;

    aiProcessing = true;
    const { event, resolve } = aiQueue.shift();

    try {
        const result = await performAIAnalysis(event);
        resolve(result);
    } catch (err) {
        resolve({ risk_score: -1, analysis: `Queue error: ${err.message}` });
    }

    aiProcessing = false;
    if (aiQueue.length > 0) {
        setImmediate(processAIQueue);
    }
}

function queueAIAnalysis(event) {
    return new Promise((resolve) => {
        aiQueue.push({ event, resolve });
        processAIQueue();
    });
}

async function performAIAnalysis(event) {
    if (!groq) {
        return { risk_score: -1, analysis: "AI service not initialized" };
    }

    try {
        const prompt = `You are a senior SOC analyst reviewing a security event from an eBPF-based Linux endpoint detection system. Analyze this event for potential threats:

EVENT DATA:
- Executable Path: ${event.fname || 'N/A'}
- Process Name: ${event.comm}
- Process ID: ${event.pid}
- eBPF Threat Level: ${event.threat_level || 0} (0=safe, 1=suspicious, 2=critical/blocked)
${event.dst_ip ? `- Network Destination: ${event.dst_ip}:${event.dst_port}` : ''}
${event.renamed_binary ? `
*** CRITICAL DETECTION ***
This binary has been IDENTIFIED via SHA-256 hash matching as: ${event.renamed_binary.detectedAs}
The file was RENAMED to disguise its true identity. This is DEFINITELY a threat.
Original path: ${event.renamed_binary.originalPath}
Threat classification: ${event.renamed_binary.threatLevel}
` : ''}

Provide a comprehensive security assessment. Consider:
1. What is the legitimate use of this command?
2. How could an attacker abuse it?
3. What MITRE ATT&CK techniques might this relate to?
4. What should a security team do?

Respond with ONLY a JSON object:
{
  "risk_score": <1-10>,
  "verdict": "<SAFE|SUSPICIOUS|MALICIOUS|CRITICAL>",
  "analysis": "<detailed 2-3 sentence explanation>",
  "attack_technique": "<MITRE ATT&CK ID if applicable, e.g. T1059>",
  "recommendation": "<what SOC should do>"
}`;

        console.log('[AI] Processing from queue...');

        const chatCompletion = await groq.chat.completions.create({
            messages: [
                { role: "system", content: "You are an expert cybersecurity analyst specializing in Linux endpoint detection and MITRE ATT&CK framework. Always respond with valid JSON only." },
                { role: "user", content: prompt }
            ],
            model: "llama-3.3-70b-versatile",
            temperature: 0.4,
            max_tokens: 350
        });

        const response = chatCompletion.choices[0]?.message?.content || '{}';
        console.log('[AI] Response received');

        const jsonMatch = response.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
            const parsed = JSON.parse(jsonMatch[0]);
            return {
                risk_score: parsed.risk_score || 5,
                verdict: parsed.verdict || 'SUSPICIOUS',
                analysis: parsed.analysis || "Analysis completed",
                attack_technique: parsed.attack_technique || null,
                recommendation: parsed.recommendation || null
            };
        }

        return { risk_score: 5, verdict: 'UNKNOWN', analysis: "Could not parse AI response" };
    } catch (error) {
        console.error('[AI] Error:', error.message);
        if (error.message.includes('401')) {
            return { risk_score: -1, analysis: "API key invalid" };
        }
        if (error.message.includes('429')) {
            return { risk_score: -1, analysis: "Rate limit exceeded" };
        }
        return { risk_score: -1, analysis: `AI error: ${error.message}` };
    }
}

// Stats
let stats = {
    total_events: 0,
    filtered_events: 0,
    threats_detected: 0,
    ai_analyses: 0,
    blocked_count: 0,
    network_connections: 0
};

// GeoIP Connection Log
const connectionLog = [];
const MAX_CONNECTIONS = 50;

function enrichWithGeoIP(event) {
    if (event.dst_ip && event.dst_ip !== '0.0.0.0' && !event.dst_ip.startsWith('127.')) {
        const geo = geoip.lookup(event.dst_ip);
        if (geo) {
            return {
                ...event,
                geo: {
                    country: geo.country,
                    city: geo.city || 'Unknown',
                    ll: geo.ll,
                    timezone: geo.timezone
                }
            };
        }
    }
    return event;
}

function addToConnectionLog(event) {
    if (event.geo && event.geo.ll) {
        const connection = {
            id: Date.now(),
            dst_ip: event.dst_ip,
            dst_port: event.dst_port,
            comm: event.comm,
            pid: event.pid,
            country: event.geo.country,
            city: event.geo.city,
            lat: event.geo.ll[0],
            lon: event.geo.ll[1],
            timestamp: new Date().toISOString(),
            is_threat: event.is_threat || false
        };
        connectionLog.unshift(connection);
        if (connectionLog.length > MAX_CONNECTIONS) {
            connectionLog.pop();
        }
        io.emit('geo_connection', connection);
    }
}

// ============================================
// DATABASE: Insert Event
// ============================================
function saveEventToDB(event, severity, aiAnalysis) {
    try {
        const timestamp = new Date().toISOString();
        const details = JSON.stringify(event);
        const aiJson = aiAnalysis ? JSON.stringify(aiAnalysis) : null;

        insertEventStmt.run(
            timestamp,
            event.type || 'EXEC',
            severity,
            event.comm || null,
            event.pid || null,
            details,
            aiJson
        );
    } catch (err) {
        console.error('[DB] Insert error:', err.message);
    }
}

// ============================================
// API: Event Ingestion
// ============================================
app.post('/api/ingest', async (req, res) => {
    const event = req.body;
    stats.total_events++;

    // Skip whitelisted processes
    if (isWhitelisted(event)) {
        res.json({ status: 'ok', filtered: true });
        return;
    }

    stats.filtered_events++;
    let enrichedEvent = { ...event };
    let aiAnalysis = null;

    // NEW: Check if binary matches known dangerous hash (catches renamed tools)
    let hashMatch = null;
    if (event.type === 'EXEC' && event.fname) {
        hashMatch = await checkBinaryHash(event.fname);
        if (hashMatch) {
            console.log(`[!!!] RENAMED TOOL DETECTED: ${event.fname} is actually ${hashMatch.originalName}!`);
            enrichedEvent.renamed_binary = {
                detectedAs: hashMatch.originalName,
                threatLevel: hashMatch.threatLevel,
                description: hashMatch.description,
                originalPath: hashMatch.originalPath
            };
            // CRITICAL: Set threat level so dashboard shows proper badge
            enrichedEvent.threat_level = hashMatch.threatLevel === 'HIGH' ? 2 : 1;
            enrichedEvent.is_threat = true;
            stats.threats_detected++;
        }
    }

    // Trigger AI analysis for EXEC and MEMFD events
    const suspicious = hashMatch || ((event.type === 'EXEC' || event.type === 'MEMFD') && isSuspicious(event));

    if (suspicious) {
        if (!hashMatch) stats.threats_detected++;
        console.log(`[!] THREAT: PID=${event.pid} COMM=${event.comm} FNAME=${event.fname}${hashMatch ? ` (RENAMED: ${hashMatch.originalName})` : ''}`);

        addToThreatLog(event);

        if (event.threat_level >= 2) {
            stats.blocked_count++;
        }

        // AI analysis - pass enrichedEvent to include renamed_binary info
        aiAnalysis = await queueAIAnalysis(enrichedEvent);
        stats.ai_analyses++;

        addToAIHistory(event, aiAnalysis);

        enrichedEvent.ai_analysis = aiAnalysis;
        enrichedEvent.is_threat = true;
        console.log(`[AI] Score=${aiAnalysis.risk_score} Verdict=${aiAnalysis.verdict}`);
    }

    // GeoIP for network events
    if (event.type === 'NET' && event.dst_ip) {
        enrichedEvent = enrichWithGeoIP(enrichedEvent);
        if (enrichedEvent.geo) {
            stats.network_connections++;
            addToConnectionLog(enrichedEvent);
            console.log(`[GEO] ${event.dst_ip} -> ${enrichedEvent.geo.country} (${enrichedEvent.geo.city})`);
        }
    }

    // PERSIST TO DATABASE
    const severity = getSeverity(enrichedEvent);
    saveEventToDB(event, severity, aiAnalysis);

    // Emit to connected frontends
    io.emit('security_event', enrichedEvent);

    if (stats.filtered_events % 100 === 0) {
        console.log(`[INFO] Processed ${stats.filtered_events} events (${stats.total_events} total, ${stats.threats_detected} threats)`);
    }

    res.json({ status: 'ok', event_id: stats.total_events });
});

// ============================================
// API: History (Paginated)
// ============================================
app.get('/api/history', (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 50, 500);
    const offset = (page - 1) * limit;

    const severity = req.query.severity;
    const type = req.query.type;
    const search = req.query.search;

    let whereClause = '1=1';
    const params = [];

    if (severity && severity !== 'all') {
        whereClause += ' AND severity = ?';
        params.push(severity);
    }
    if (type && type !== 'all') {
        whereClause += ' AND type = ?';
        params.push(type);
    }
    if (search) {
        whereClause += ' AND (process_name LIKE ? OR details LIKE ?)';
        params.push(`%${search}%`, `%${search}%`);
    }

    const countStmt = db.prepare(`SELECT COUNT(*) as total FROM events WHERE ${whereClause}`);
    const total = countStmt.get(...params).total;

    const selectStmt = db.prepare(`
        SELECT id, timestamp, type, severity, process_name, pid, details, ai_analysis
        FROM events
        WHERE ${whereClause}
        ORDER BY id DESC
        LIMIT ? OFFSET ?
    `);

    const events = selectStmt.all(...params, limit, offset).map(row => ({
        id: row.id,
        timestamp: row.timestamp,
        type: row.type,
        severity: row.severity,
        process_name: row.process_name,
        pid: row.pid,
        details: row.details ? JSON.parse(row.details) : null,
        ai_analysis: row.ai_analysis ? JSON.parse(row.ai_analysis) : null
    }));

    res.json({
        page,
        limit,
        total,
        total_pages: Math.ceil(total / limit),
        events
    });
});

// ============================================
// API: Export History to CSV
// ============================================
app.get('/api/export/history', (req, res) => {
    const severity = req.query.severity;
    const type = req.query.type;

    let whereClause = '1=1';
    const params = [];

    if (severity && severity !== 'all') {
        whereClause += ' AND severity = ?';
        params.push(severity);
    }
    if (type && type !== 'all') {
        whereClause += ' AND type = ?';
        params.push(type);
    }

    const selectStmt = db.prepare(`
        SELECT id, timestamp, type, severity, process_name, pid, details, ai_analysis
        FROM events
        WHERE ${whereClause}
        ORDER BY id DESC
        LIMIT 10000
    `);

    const events = selectStmt.all(...params);

    // Generate CSV
    const header = 'ID,Timestamp,Type,Severity,Process,PID,Path,AI Risk Score,AI Verdict\n';
    const rows = events.map(row => {
        const details = row.details ? JSON.parse(row.details) : {};
        const ai = row.ai_analysis ? JSON.parse(row.ai_analysis) : {};
        return [
            row.id,
            row.timestamp,
            row.type,
            row.severity,
            row.process_name || '',
            row.pid || '',
            details.fname || '',
            ai.risk_score || '',
            ai.verdict || ''
        ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(',');
    }).join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename=kernel-watch-history-${new Date().toISOString().slice(0, 10)}.csv`);
    res.send(header + rows);
});

// ============================================
// API: Dynamic Whitelist
// ============================================
app.get('/api/whitelist', (req, res) => {
    const entries = db.prepare('SELECT * FROM whitelist ORDER BY added_at DESC').all();
    res.json({ total: entries.length, entries });
});

app.post('/api/actions/whitelist', (req, res) => {
    const { process_name, reason } = req.body;

    if (!process_name) {
        return res.status(400).json({ error: 'process_name is required' });
    }

    try {
        const result = insertWhitelistStmt.run(process_name, new Date().toISOString(), reason || 'Marked as false positive');

        if (result.changes > 0) {
            // Update in-memory set
            dynamicWhitelist.add(process_name);
            console.log(`[WHITELIST] Added: ${process_name}`);

            // Notify all connected clients
            io.emit('whitelist_updated', { action: 'add', process_name });

            res.json({ success: true, message: `${process_name} added to whitelist` });
        } else {
            res.json({ success: false, message: 'Already whitelisted' });
        }
    } catch (err) {
        console.error('[WHITELIST] Error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/whitelist/:id', (req, res) => {
    const id = parseInt(req.params.id);

    try {
        const entry = db.prepare('SELECT process_name FROM whitelist WHERE id = ?').get(id);
        if (!entry) {
            return res.status(404).json({ error: 'Entry not found' });
        }

        db.prepare('DELETE FROM whitelist WHERE id = ?').run(id);

        // Update in-memory set
        dynamicWhitelist.delete(entry.process_name);
        console.log(`[WHITELIST] Removed: ${entry.process_name}`);

        // Notify all connected clients
        io.emit('whitelist_updated', { action: 'remove', process_name: entry.process_name });

        res.json({ success: true, message: `${entry.process_name} removed from whitelist` });
    } catch (err) {
        console.error('[WHITELIST] Error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// ============================================
// API: Existing Endpoints
// ============================================
app.get('/api/export/threats', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename=threats.json');
    res.json({
        exported_at: new Date().toISOString(),
        total_threats: threatLog.length,
        threats: threatLog
    });
});

app.get('/api/export/stats', (req, res) => {
    res.json({
        exported_at: new Date().toISOString(),
        stats: stats,
        ai_queue_length: aiQueue.length,
        threat_log_size: threatLog.length
    });
});

app.get('/api/threats', (req, res) => {
    res.json(threatLog);
});

app.get('/api/connections', (req, res) => {
    res.json({
        total: connectionLog.length,
        connections: connectionLog
    });
});

app.get('/api/test-ai', async (req, res) => {
    const testEvent = {
        fname: '/usr/bin/nc',
        comm: 'nc',
        pid: 12345,
        threat_level: 0
    };

    console.log('[TEST] Running AI test...');
    const result = await queueAIAnalysis(testEvent);
    console.log('[TEST] Result:', result);

    res.json({ test_event: testEvent, ai_result: result });
});

app.get('/api/stats', (req, res) => {
    // Include DB stats
    const dbStats = db.prepare('SELECT COUNT(*) as total, SUM(CASE WHEN severity = "critical" THEN 1 ELSE 0 END) as critical, SUM(CASE WHEN severity = "suspicious" THEN 1 ELSE 0 END) as suspicious FROM events').get();

    res.json({
        ...stats,
        ai_queue_length: aiQueue.length,
        threat_log_size: threatLog.length,
        db_total_events: dbStats.total,
        db_critical_events: dbStats.critical || 0,
        db_suspicious_events: dbStats.suspicious || 0
    });
});

// ============================================
// Socket.io Connection
// ============================================
io.on('connection', (socket) => {
    console.log('[WS] Client connected:', socket.id);
    socket.emit('stats', stats);
    socket.emit('threat_log', threatLog);
    socket.emit('ai_history', aiHistoryLog);
    socket.emit('geo_connections', connectionLog);

    socket.on('disconnect', () => {
        console.log('[WS] Client disconnected:', socket.id);
    });
});

// ============================================
// Graceful Shutdown
// ============================================
process.on('SIGINT', () => {
    console.log('\n[DB] Closing database...');
    db.close();
    process.exit(0);
});

process.on('SIGTERM', () => {
    console.log('\n[DB] Closing database...');
    db.close();
    process.exit(0);
});

// Start Server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log('='.repeat(50));
    console.log('  KERNEL-WATCH // THE BRAIN v3.0');
    console.log('='.repeat(50));
    console.log(`  Server running on port ${PORT}`);
    console.log(`  Groq AI: ${groq ? 'Ready' : 'NOT AVAILABLE'}`);
    console.log(`  Database: ${DB_PATH}`);
    console.log('  ');
    console.log('  FEATURES ACTIVE:');
    console.log('  ✓ Process Whitelisting (Static + Dynamic)');
    console.log('  ✓ SQLite Persistence');
    console.log('  ✓ History API with Pagination');
    console.log('  ✓ Dynamic Whitelist Management');
    console.log('  ✓ AI Analysis Queue');
    console.log('  ✓ GeoIP Enrichment');
    console.log('  ✓ CSV Export');
    console.log('='.repeat(50));
});
