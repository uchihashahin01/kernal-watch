import { useState, useEffect, useRef, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { io } from 'socket.io-client'
import {
    Shield, Activity, AlertTriangle, Brain, Wifi, WifiOff,
    Search, History, X, Volume2, VolumeX, Cpu, Network,
    Eye, Zap, Terminal, Lock, Clock, Download, FileJson, Globe, Map,
    Database, CheckCircle, Ban, Settings
} from 'lucide-react'
import WorldMap from './WorldMap'
import HistoryView from './History'
import WhitelistConfig from './WhitelistConfig'

const BACKEND_URL = 'http://localhost:3000'

// IMPROVEMENT 6: Larger buffer (2000 events)
const MAX_EVENTS = 2000
const MAX_DISPLAY_EVENTS = 200

function Dashboard() {
    const [events, setEvents] = useState([])
    const [stats, setStats] = useState({ safe: 0, threats: 0, total: 0, execCount: 0, netCount: 0, blocked: 0 })
    const [latestAI, setLatestAI] = useState(null)
    const [aiHistory, setAiHistory] = useState([])
    const [connected, setConnected] = useState(false)
    const [showAiHistory, setShowAiHistory] = useState(false)
    const [selectedEvent, setSelectedEvent] = useState(null)
    const [searchTerm, setSearchTerm] = useState('')
    const [showThreatsOnly, setShowThreatsOnly] = useState(false)
    const [filterType, setFilterType] = useState('ALL')
    const [currentTime, setCurrentTime] = useState(new Date())
    const [recentThreats, setRecentThreats] = useState([])

    // WORLD MAP: GeoIP Connections
    const [geoConnections, setGeoConnections] = useState([])
    const [showMap, setShowMap] = useState(false)

    // HISTORY TAB
    const [showHistory, setShowHistory] = useState(false)

    // WHITELIST CONFIG TAB
    const [showWhitelistConfig, setShowWhitelistConfig] = useState(false)

    // WHITELIST STATE
    const [whitelistStatus, setWhitelistStatus] = useState(null)

    // IMPROVEMENT 5: Sound Alerts
    const [audioEnabled, setAudioEnabled] = useState(false)
    const audioContextRef = useRef(null)

    // Sound alert function
    const playAlertSound = useCallback(() => {
        if (!audioEnabled) return

        try {
            if (!audioContextRef.current) {
                audioContextRef.current = new (window.AudioContext || window.webkitAudioContext)()
            }
            const ctx = audioContextRef.current
            const oscillator = ctx.createOscillator()
            const gainNode = ctx.createGain()

            oscillator.connect(gainNode)
            gainNode.connect(ctx.destination)

            oscillator.frequency.setValueAtTime(880, ctx.currentTime)
            oscillator.frequency.setValueAtTime(440, ctx.currentTime + 0.1)
            oscillator.frequency.setValueAtTime(880, ctx.currentTime + 0.2)

            gainNode.gain.setValueAtTime(0.3, ctx.currentTime)
            gainNode.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.4)

            oscillator.start(ctx.currentTime)
            oscillator.stop(ctx.currentTime + 0.4)
        } catch (e) {
            console.log('Audio not supported')
        }
    }, [audioEnabled])

    // WHITELIST: Mark as False Positive
    const markAsFalsePositive = async (processName) => {
        try {
            const response = await fetch(`${BACKEND_URL}/api/actions/whitelist`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    process_name: processName,
                    reason: 'Marked as false positive from dashboard'
                })
            })
            const data = await response.json()
            if (data.success) {
                setWhitelistStatus({ type: 'success', message: `${processName} added to whitelist` })
                setTimeout(() => {
                    setWhitelistStatus(null)
                    setSelectedEvent(null)
                }, 2000)
            } else {
                setWhitelistStatus({ type: 'info', message: data.message || 'Already whitelisted' })
                setTimeout(() => setWhitelistStatus(null), 2000)
            }
        } catch (e) {
            setWhitelistStatus({ type: 'error', message: 'Failed to whitelist' })
            setTimeout(() => setWhitelistStatus(null), 3000)
        }
    }

    // IMPROVEMENT 4: Export function
    const exportThreats = async () => {
        try {
            const response = await fetch(`${BACKEND_URL}/api/export/threats`)
            const data = await response.json()
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
            const url = URL.createObjectURL(blob)
            const a = document.createElement('a')
            a.href = url
            a.download = `threats_${new Date().toISOString().slice(0, 10)}.json`
            a.click()
            URL.revokeObjectURL(url)
        } catch (e) {
            console.error('Export failed:', e)
        }
    }

    const exportEvents = () => {
        const data = {
            exported_at: new Date().toISOString(),
            total_events: events.length,
            events: events.slice(0, 500)
        }
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `events_${new Date().toISOString().slice(0, 10)}.json`
        a.click()
        URL.revokeObjectURL(url)
    }

    useEffect(() => {
        const timer = setInterval(() => setCurrentTime(new Date()), 1000)
        return () => clearInterval(timer)
    }, [])

    useEffect(() => {
        const socket = io(BACKEND_URL)
        socket.on('connect', () => setConnected(true))
        socket.on('disconnect', () => setConnected(false))

        socket.on('security_event', (event) => {
            const isThreatEvent = event.is_threat || (event.threat_level > 0) || (event.ai_analysis?.risk_score > 5)

            // IMPROVEMENT 6: Larger buffer
            setEvents(prev => [event, ...prev].slice(0, MAX_EVENTS))

            setStats(prev => ({
                total: prev.total + 1,
                threats: isThreatEvent ? prev.threats + 1 : prev.threats,
                safe: !isThreatEvent ? prev.safe + 1 : prev.safe,
                execCount: event.type === 'EXEC' ? prev.execCount + 1 : prev.execCount,
                netCount: event.type === 'NET' ? prev.netCount + 1 : prev.netCount,
                blocked: event.threat_level >= 2 ? prev.blocked + 1 : prev.blocked
            }))

            if (isThreatEvent) {
                setRecentThreats(prev => [event, ...prev].slice(0, 10))
                // IMPROVEMENT 5: Play sound for threats
                playAlertSound()
            }

            if (event.ai_analysis) {
                const aiEntry = {
                    ...event.ai_analysis,
                    command: event.fname || event.comm,
                    pid: event.pid,
                    timestamp: new Date().toLocaleTimeString(),
                    id: Date.now()
                }
                setLatestAI(aiEntry)
                setAiHistory(prev => [aiEntry, ...prev].slice(0, 50))
            }
        })

        // Receive threat log on connect
        socket.on('threat_log', (threats) => {
            if (threats && threats.length > 0) {
                setRecentThreats(threats.slice(0, 10))
            }
        })

        // Receive AI history on connect (persistent across refreshes)
        socket.on('ai_history', (history) => {
            if (history && history.length > 0) {
                setAiHistory(history)
            }
        })

        socket.on('stats', (s) => s && setStats(prev => ({
            ...prev,
            total: s.total_events || s.filtered_events || 0,
            threats: s.threats_detected || 0,
            safe: (s.filtered_events || s.total_events || 0) - (s.threats_detected || 0),
            blocked: s.blocked_count || 0
        })))

        // WORLD MAP: Receive geo connections
        socket.on('geo_connection', (conn) => {
            if (conn && conn.lat && conn.lon) {
                setGeoConnections(prev => [conn, ...prev].slice(0, 50))
            }
        })

        // Receive initial geo connections on connect
        socket.on('geo_connections', (connections) => {
            if (connections && connections.length > 0) {
                setGeoConnections(connections)
            }
        })

        // Listen for whitelist updates
        socket.on('whitelist_updated', (data) => {
            console.log('[WS] Whitelist updated:', data)
        })

        return () => socket.disconnect()
    }, [playAlertSound])

    const filteredEvents = events.filter(e => {
        const isThreat = e.is_threat || (e.threat_level > 0) || (e.ai_analysis?.risk_score > 5)
        if (showThreatsOnly && !isThreat) return false
        if (filterType !== 'ALL' && e.type !== filterType) return false
        if (searchTerm && !e.comm?.toLowerCase().includes(searchTerm.toLowerCase()) && !e.fname?.toLowerCase().includes(searchTerm.toLowerCase()) && !String(e.pid).includes(searchTerm)) return false
        return true
    })

    const formatTime = (ts) => ts ? new Date(ts * 1000).toLocaleTimeString() : '--:--:--'
    const getRisk = (s) => s >= 7 ? { l: 'CRITICAL', c: 'critical' } : s >= 4 ? { l: 'WARNING', c: 'warning' } : { l: 'SAFE', c: 'safe' }
    const isThreat = (e) => e.is_threat || (e.threat_level > 0) || (e.ai_analysis?.risk_score > 5)

    // Show Whitelist Config View
    if (showWhitelistConfig) {
        return <WhitelistConfig onBack={() => setShowWhitelistConfig(false)} />
    }

    // Show History View
    if (showHistory) {
        return <HistoryView onBack={() => setShowHistory(false)} />
    }

    return (
        <div className="soc-dashboard">
            {/* Modal */}
            <AnimatePresence>
                {selectedEvent && (
                    <motion.div className="modal-overlay" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => setSelectedEvent(null)}>
                        <motion.div className="modal-content" initial={{ scale: 0.8, y: 50 }} animate={{ scale: 1, y: 0 }} exit={{ scale: 0.8, y: 50 }} onClick={e => e.stopPropagation()}>
                            <div className="modal-header"><Terminal size={18} /><span>Event Analysis</span><X size={18} onClick={() => setSelectedEvent(null)} /></div>
                            <div className="modal-body">
                                <div className="modal-grid">
                                    <div className="modal-field"><label>Type</label><span className={`type-badge ${selectedEvent.type?.toLowerCase()}`}>{selectedEvent.type}</span></div>
                                    <div className="modal-field"><label>PID</label><span className="mono">{selectedEvent.pid}</span></div>
                                    <div className="modal-field"><label>Process</label><span className="mono highlight">{selectedEvent.comm}</span></div>
                                    <div className="modal-field"><label>Threat Level</label><span className={selectedEvent.threat_level >= 2 ? 'danger' : selectedEvent.threat_level === 1 ? 'warning' : 'safe'}>{selectedEvent.threat_level >= 2 ? 'CRITICAL' : selectedEvent.threat_level === 1 ? 'SUSPICIOUS' : 'SAFE'}</span></div>
                                </div>
                                {selectedEvent.fname && <div className="modal-path"><label>Executable Path</label><code>{selectedEvent.fname}</code></div>}
                                {selectedEvent.dst_ip && <div className="modal-path"><label>Network Destination</label><code>{selectedEvent.dst_ip}:{selectedEvent.dst_port}</code></div>}
                                {selectedEvent.ai_analysis && (
                                    <div className="modal-ai">
                                        <div className="ai-header"><Brain size={16} /><span>Groq AI Security Analysis</span><span className={`risk-pill ${getRisk(selectedEvent.ai_analysis.risk_score).c}`}>{selectedEvent.ai_analysis.risk_score}/10</span></div>
                                        {selectedEvent.ai_analysis.verdict && <div className="ai-verdict-row"><span className="label">Verdict:</span><span className={`verdict ${selectedEvent.ai_analysis.verdict?.toLowerCase()}`}>{selectedEvent.ai_analysis.verdict}</span></div>}
                                        <p className="ai-analysis-text">{selectedEvent.ai_analysis.analysis}</p>
                                        {selectedEvent.ai_analysis.attack_technique && <div className="ai-field"><span className="label">MITRE ATT&CK:</span><span className="technique">{selectedEvent.ai_analysis.attack_technique}</span></div>}
                                        {selectedEvent.ai_analysis.recommendation && <div className="ai-recommendation"><span className="label">Recommendation:</span><span>{selectedEvent.ai_analysis.recommendation}</span></div>}
                                    </div>
                                )}

                                {/* WHITELIST ACTION for threat events */}
                                {isThreat(selectedEvent) && (
                                    <div className="modal-actions">
                                        {whitelistStatus ? (
                                            <div className={`whitelist-status ${whitelistStatus.type}`}>
                                                {whitelistStatus.type === 'success' && <CheckCircle size={16} />}
                                                {whitelistStatus.message}
                                            </div>
                                        ) : (
                                            <button
                                                className="whitelist-btn"
                                                onClick={() => markAsFalsePositive(selectedEvent.comm)}
                                            >
                                                <Ban size={14} />
                                                Mark as False Positive
                                            </button>
                                        )}
                                    </div>
                                )}

                                <details className="raw-data"><summary>Raw JSON</summary><pre>{JSON.stringify(selectedEvent, null, 2)}</pre></details>
                            </div>
                        </motion.div>
                    </motion.div>
                )}
            </AnimatePresence>

            {/* Top Bar */}
            <header className="top-bar">
                <div className="logo"><Shield className="logo-icon" /><span>KERNEL</span><span className="accent">WATCH</span></div>
                <div className="status-strip">
                    <div className={`status-pill ${connected ? 'online' : 'offline'}`}><div className="pulse-dot" />{connected ? 'SYSTEM ONLINE' : 'DISCONNECTED'}</div>
                    <div className="status-pill"><Clock size={14} />{currentTime.toLocaleTimeString()}</div>
                    <div className="status-pill"><Eye size={14} />MONITORING</div>
                    <button className={`audio-btn ${audioEnabled ? 'on' : ''}`} onClick={() => setAudioEnabled(!audioEnabled)} title="Toggle sound alerts">
                        {audioEnabled ? <Volume2 size={16} /> : <VolumeX size={16} />}
                    </button>
                    <button className={`map-btn ${showMap ? 'on' : ''}`} onClick={() => setShowMap(!showMap)} title="Toggle World Map">
                        <Globe size={16} />
                    </button>
                    <button className="history-btn" onClick={() => setShowHistory(true)} title="Forensic History">
                        <Database size={16} />
                    </button>
                    <button className="settings-btn" onClick={() => setShowWhitelistConfig(true)} title="Whitelist Configuration">
                        <Settings size={16} />
                    </button>
                </div>
            </header>

            {/* Stats Row */}
            <div className="stats-row">
                <motion.div className="stat-card total" whileHover={{ scale: 1.02 }}>
                    <div className="stat-icon"><Activity /></div>
                    <div className="stat-info"><span className="stat-value">{stats.total.toLocaleString()}</span><span className="stat-label">TOTAL EVENTS</span></div>
                </motion.div>
                <motion.div className="stat-card exec" whileHover={{ scale: 1.02 }}>
                    <div className="stat-icon"><Cpu /></div>
                    <div className="stat-info"><span className="stat-value">{stats.execCount.toLocaleString()}</span><span className="stat-label">PROCESS EXEC</span></div>
                </motion.div>
                <motion.div className="stat-card net" whileHover={{ scale: 1.02 }}>
                    <div className="stat-icon"><Network /></div>
                    <div className="stat-info"><span className="stat-value">{stats.netCount.toLocaleString()}</span><span className="stat-label">NETWORK CONN</span></div>
                </motion.div>
                <motion.div className="stat-card safe" whileHover={{ scale: 1.02 }}>
                    <div className="stat-icon"><Lock /></div>
                    <div className="stat-info"><span className="stat-value">{stats.safe.toLocaleString()}</span><span className="stat-label">SAFE EVENTS</span></div>
                </motion.div>
                <motion.div className="stat-card threat" whileHover={{ scale: 1.02 }} animate={stats.threats > 0 ? { boxShadow: ['0 0 0 rgba(255,50,100,0)', '0 0 30px rgba(255,50,100,0.5)', '0 0 0 rgba(255,50,100,0)'] } : {}} transition={{ repeat: Infinity, duration: 2 }}>
                    <div className="stat-icon"><AlertTriangle /></div>
                    <div className="stat-info"><span className="stat-value">{stats.threats}</span><span className="stat-label">THREATS</span></div>
                </motion.div>
                <motion.div className="stat-card blocked" whileHover={{ scale: 1.02 }} animate={stats.blocked > 0 ? { boxShadow: ['0 0 0 rgba(255,100,50,0)', '0 0 30px rgba(255,100,50,0.5)', '0 0 0 rgba(255,100,50,0)'] } : {}} transition={{ repeat: Infinity, duration: 2 }}>
                    <div className="stat-icon"><Ban /></div>
                    <div className="stat-info"><span className="stat-value">{stats.blocked}</span><span className="stat-label">BLOCKED</span></div>
                </motion.div>
            </div>

            {/* Main Grid */}
            <div className="main-grid">
                {/* Live Feed */}
                <div className="panel feed-panel">
                    <div className="panel-header">
                        <div className="panel-title"><Terminal size={16} />LIVE EVENT STREAM</div>
                        <div className="feed-controls">
                            <div className="search-input"><Search size={14} /><input placeholder="Search events..." value={searchTerm} onChange={e => setSearchTerm(e.target.value)} />{searchTerm && <X size={14} onClick={() => setSearchTerm('')} />}</div>
                            <button className={`filter-btn ${showThreatsOnly ? 'active' : ''}`} onClick={() => setShowThreatsOnly(!showThreatsOnly)}><AlertTriangle size={12} />THREATS</button>
                            <select value={filterType} onChange={e => setFilterType(e.target.value)}>
                                <option value="ALL">ALL</option>
                                <option value="EXEC">EXEC</option>
                                <option value="NET">NET</option>
                                <option value="MEMFD">MEMFD</option>
                            </select>
                            <button className="export-btn" onClick={exportEvents} title="Export events"><Download size={14} /></button>
                        </div>
                    </div>
                    <div className="event-list">
                        <AnimatePresence>
                            {filteredEvents.length === 0 ? <div className="empty-state"><Zap />Awaiting events...</div> : filteredEvents.slice(0, MAX_DISPLAY_EVENTS).map((e, i) => (
                                <motion.div key={`${e.pid}-${i}`} className={`event-row ${isThreat(e) ? 'threat' : ''}`} initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} onClick={() => setSelectedEvent(e)}>
                                    <span className="event-time">{formatTime(e.timestamp)}</span>
                                    <span className={`event-type ${e.type?.toLowerCase()}`}>{e.type}</span>
                                    <span className="event-pid">PID:{e.pid}</span>
                                    <span className="event-comm">{e.comm}</span>
                                    <span className="event-path">{e.fname?.slice(-50) || e.dst_ip || ''}</span>
                                    {e.threat_level >= 2 && <span className="threat-badge critical"><Zap size={10} />CRITICAL</span>}
                                    {e.threat_level === 1 && <span className="threat-badge suspicious"><AlertTriangle size={10} />SUSPICIOUS</span>}
                                    {e.ai_analysis && <span className={`ai-score ${getRisk(e.ai_analysis.risk_score).c}`}>{e.ai_analysis.risk_score}</span>}
                                </motion.div>
                            ))}
                        </AnimatePresence>
                    </div>
                    <div className="panel-footer">{filteredEvents.length} events | Buffer: {events.length}/{MAX_EVENTS} | Click row for details</div>
                </div>

                {/* World Map Panel (conditional) */}
                {showMap && (
                    <div className="panel map-panel">
                        <WorldMap
                            connections={geoConnections}
                            onConnectionClick={(conn) => {
                                const event = events.find(e => e.dst_ip === conn.dst_ip)
                                if (event) setSelectedEvent(event)
                            }}
                        />
                    </div>
                )}

                {/* Right Sidebar */}
                <div className="sidebar-panels">
                    {/* Recent Threats */}
                    <div className="panel threats-panel">
                        <div className="panel-header">
                            <div className="panel-title"><AlertTriangle size={16} />RECENT THREATS</div>
                            <button className="export-btn small" onClick={exportThreats} title="Export threats"><FileJson size={14} /></button>
                        </div>
                        <div className="threats-list">
                            {recentThreats.length === 0 ? <div className="empty-state small"><Lock />No threats detected</div> : recentThreats.map((t, i) => (
                                <motion.div key={i} className="threat-item" initial={{ opacity: 0 }} animate={{ opacity: 1 }} onClick={() => setSelectedEvent(t)}>
                                    <div className="threat-main"><Zap size={12} className="threat-icon" /><span className="threat-comm">{t.comm}</span></div>
                                    <div className="threat-path">{t.fname?.slice(-40)}</div>
                                </motion.div>
                            ))}
                        </div>
                    </div>

                    {/* AI Panel */}
                    <div className="panel ai-panel">
                        <div className="panel-header">
                            <div className="panel-title"><Brain size={16} />GROQ AI ANALYSIS</div>
                            <button className="history-toggle" onClick={() => setShowAiHistory(!showAiHistory)}><History size={14} />{aiHistory.length}</button>
                        </div>
                        {showAiHistory ? (
                            <div className="ai-history">
                                {aiHistory.length === 0 ? <div className="empty-state small">No analyses</div> : aiHistory.map(a => (
                                    <div key={a.id} className="history-item">
                                        <div className="history-top"><span className={`risk-pill small ${getRisk(a.risk_score).c}`}>{a.risk_score}/10</span><span className="time">{a.timestamp}</span></div>
                                        <div className="history-cmd">{a.command}</div>
                                        <div className="history-text">{a.analysis}</div>
                                    </div>
                                ))}
                            </div>
                        ) : (
                            <div className="ai-current">
                                {!latestAI ? <div className="empty-state"><Eye />Monitoring for suspicious activity...</div> : (
                                    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} key={latestAI.id}>
                                        <div className="ai-score-display"><span>Risk Score</span><motion.span className={`score-value ${getRisk(latestAI.risk_score).c}`} animate={latestAI.risk_score >= 7 ? { scale: [1, 1.1, 1] } : {}} transition={{ repeat: Infinity, duration: 1 }}>{latestAI.risk_score}<small>/10</small></motion.span></div>
                                        <div className={`ai-verdict-badge ${(latestAI.verdict || getRisk(latestAI.risk_score).l).toLowerCase()}`}>{latestAI.verdict || getRisk(latestAI.risk_score).l}</div>
                                        <p className="ai-analysis">{latestAI.analysis}</p>
                                        {latestAI.attack_technique && <div className="ai-technique"><span>ATT&CK:</span> {latestAI.attack_technique}</div>}
                                        {latestAI.recommendation && <div className="ai-rec"><span>Action:</span> {latestAI.recommendation}</div>}
                                        <div className="ai-meta"><span>{latestAI.command}</span><span>PID: {latestAI.pid}</span></div>
                                    </motion.div>
                                )}
                            </div>
                        )}
                    </div>
                </div>
            </div>

            {/* Footer */}
            <footer className="bottom-bar">
                <span>KERNEL-WATCH v3.0 // eBPF Security Monitor + SQLite Persistence</span>
                <span>Backend: {connected ? '●' : '○'} {connected ? 'Connected' : 'Offline'} | AI: Groq Llama 3.3 70B | Buffer: {events.length}</span>
            </footer>
        </div>
    )
}

export default Dashboard
