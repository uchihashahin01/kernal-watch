import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
    Database, Search, Download, ChevronLeft, ChevronRight,
    Filter, X, Terminal, Brain, AlertTriangle, Shield, RefreshCw
} from 'lucide-react'

const BACKEND_URL = 'http://localhost:3000'

function History({ onBack }) {
    const [events, setEvents] = useState([])
    const [loading, setLoading] = useState(true)
    const [page, setPage] = useState(1)
    const [totalPages, setTotalPages] = useState(1)
    const [total, setTotal] = useState(0)
    const [limit] = useState(50)

    // Filters
    const [severity, setSeverity] = useState('all')
    const [type, setType] = useState('all')
    const [search, setSearch] = useState('')
    const [searchInput, setSearchInput] = useState('')

    // Modal
    const [selectedEvent, setSelectedEvent] = useState(null)

    const fetchHistory = useCallback(async () => {
        setLoading(true)
        try {
            const params = new URLSearchParams({
                page: page.toString(),
                limit: limit.toString()
            })
            if (severity !== 'all') params.append('severity', severity)
            if (type !== 'all') params.append('type', type)
            if (search) params.append('search', search)

            const response = await fetch(`${BACKEND_URL}/api/history?${params}`)
            const data = await response.json()

            setEvents(data.events)
            setTotalPages(data.total_pages)
            setTotal(data.total)
        } catch (e) {
            console.error('Failed to fetch history:', e)
        }
        setLoading(false)
    }, [page, limit, severity, type, search])

    useEffect(() => {
        fetchHistory()
    }, [fetchHistory])

    const handleSearch = () => {
        setSearch(searchInput)
        setPage(1)
    }

    const clearFilters = () => {
        setSeverity('all')
        setType('all')
        setSearch('')
        setSearchInput('')
        setPage(1)
    }

    const exportCSV = () => {
        const params = new URLSearchParams()
        if (severity !== 'all') params.append('severity', severity)
        if (type !== 'all') params.append('type', type)

        window.open(`${BACKEND_URL}/api/export/history?${params}`, '_blank')
    }

    const formatDate = (ts) => {
        const d = new Date(ts)
        return d.toLocaleDateString() + ' ' + d.toLocaleTimeString()
    }

    const getSeverityClass = (s) => {
        if (s === 'critical') return 'severity-critical'
        if (s === 'suspicious') return 'severity-suspicious'
        return 'severity-safe'
    }

    const getRisk = (s) => s >= 7 ? { l: 'CRITICAL', c: 'critical' } : s >= 4 ? { l: 'WARNING', c: 'warning' } : { l: 'SAFE', c: 'safe' }

    return (
        <div className="history-container">
            {/* Modal */}
            <AnimatePresence>
                {selectedEvent && (
                    <motion.div className="modal-overlay" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => setSelectedEvent(null)}>
                        <motion.div className="modal-content" initial={{ scale: 0.8, y: 50 }} animate={{ scale: 1, y: 0 }} exit={{ scale: 0.8, y: 50 }} onClick={e => e.stopPropagation()}>
                            <div className="modal-header"><Terminal size={18} /><span>Event Details</span><X size={18} onClick={() => setSelectedEvent(null)} /></div>
                            <div className="modal-body">
                                <div className="modal-grid">
                                    <div className="modal-field"><label>ID</label><span className="mono">{selectedEvent.id}</span></div>
                                    <div className="modal-field"><label>Timestamp</label><span>{formatDate(selectedEvent.timestamp)}</span></div>
                                    <div className="modal-field"><label>Type</label><span className={`type-badge ${selectedEvent.type?.toLowerCase()}`}>{selectedEvent.type}</span></div>
                                    <div className="modal-field"><label>Severity</label><span className={getSeverityClass(selectedEvent.severity)}>{selectedEvent.severity?.toUpperCase()}</span></div>
                                    <div className="modal-field"><label>Process</label><span className="mono highlight">{selectedEvent.process_name}</span></div>
                                    <div className="modal-field"><label>PID</label><span className="mono">{selectedEvent.pid}</span></div>
                                </div>
                                {selectedEvent.details?.fname && <div className="modal-path"><label>Executable Path</label><code>{selectedEvent.details.fname}</code></div>}
                                {selectedEvent.details?.dst_ip && <div className="modal-path"><label>Network Destination</label><code>{selectedEvent.details.dst_ip}:{selectedEvent.details.dst_port}</code></div>}
                                {selectedEvent.ai_analysis && (
                                    <div className="modal-ai">
                                        <div className="ai-header"><Brain size={16} /><span>AI Security Analysis</span><span className={`risk-pill ${getRisk(selectedEvent.ai_analysis.risk_score).c}`}>{selectedEvent.ai_analysis.risk_score}/10</span></div>
                                        {selectedEvent.ai_analysis.verdict && <div className="ai-verdict-row"><span className="label">Verdict:</span><span className={`verdict ${selectedEvent.ai_analysis.verdict?.toLowerCase()}`}>{selectedEvent.ai_analysis.verdict}</span></div>}
                                        <p className="ai-analysis-text">{selectedEvent.ai_analysis.analysis}</p>
                                        {selectedEvent.ai_analysis.attack_technique && <div className="ai-field"><span className="label">MITRE ATT&CK:</span><span className="technique">{selectedEvent.ai_analysis.attack_technique}</span></div>}
                                        {selectedEvent.ai_analysis.recommendation && <div className="ai-recommendation"><span className="label">Recommendation:</span><span>{selectedEvent.ai_analysis.recommendation}</span></div>}
                                    </div>
                                )}
                                <details className="raw-data"><summary>Raw JSON</summary><pre>{JSON.stringify(selectedEvent, null, 2)}</pre></details>
                            </div>
                        </motion.div>
                    </motion.div>
                )}
            </AnimatePresence>

            {/* Header */}
            <div className="history-header">
                <div className="history-title">
                    <button className="back-btn" onClick={onBack}><ChevronLeft size={18} />Back</button>
                    <Database size={20} />
                    <span>FORENSIC HISTORY</span>
                    <span className="history-count">{total.toLocaleString()} events</span>
                </div>
                <div className="history-actions">
                    <button className="refresh-btn" onClick={fetchHistory} disabled={loading}>
                        <RefreshCw size={14} className={loading ? 'spinning' : ''} />
                    </button>
                    <button className="export-btn" onClick={exportCSV}>
                        <Download size={14} />Export CSV
                    </button>
                </div>
            </div>

            {/* Filters */}
            <div className="history-filters">
                <div className="search-input">
                    <Search size={14} />
                    <input
                        placeholder="Search process or path..."
                        value={searchInput}
                        onChange={e => setSearchInput(e.target.value)}
                        onKeyDown={e => e.key === 'Enter' && handleSearch()}
                    />
                    {searchInput && <X size={14} onClick={() => { setSearchInput(''); setSearch(''); setPage(1); }} />}
                </div>

                <div className="filter-group">
                    <label><Filter size={12} />Severity</label>
                    <select value={severity} onChange={e => { setSeverity(e.target.value); setPage(1); }}>
                        <option value="all">All</option>
                        <option value="safe">Safe</option>
                        <option value="suspicious">Suspicious</option>
                        <option value="critical">Critical</option>
                    </select>
                </div>

                <div className="filter-group">
                    <label>Type</label>
                    <select value={type} onChange={e => { setType(e.target.value); setPage(1); }}>
                        <option value="all">All</option>
                        <option value="EXEC">EXEC</option>
                        <option value="NET">NET</option>
                        <option value="MEMFD">MEMFD</option>
                    </select>
                </div>

                {(severity !== 'all' || type !== 'all' || search) && (
                    <button className="clear-filters" onClick={clearFilters}>
                        <X size={12} />Clear
                    </button>
                )}
            </div>

            {/* Table */}
            <div className="history-table-container">
                {loading ? (
                    <div className="loading-state"><RefreshCw className="spinning" />Loading...</div>
                ) : events.length === 0 ? (
                    <div className="empty-state"><Database />No events found</div>
                ) : (
                    <table className="history-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Timestamp</th>
                                <th>Type</th>
                                <th>Severity</th>
                                <th>Process</th>
                                <th>Path / Destination</th>
                                <th>AI Score</th>
                            </tr>
                        </thead>
                        <tbody>
                            {events.map(event => (
                                <motion.tr
                                    key={event.id}
                                    className={`history-row ${event.severity === 'critical' ? 'threat' : ''}`}
                                    initial={{ opacity: 0 }}
                                    animate={{ opacity: 1 }}
                                    onClick={() => setSelectedEvent(event)}
                                >
                                    <td className="mono">{event.id}</td>
                                    <td>{formatDate(event.timestamp)}</td>
                                    <td><span className={`type-badge ${event.type?.toLowerCase()}`}>{event.type}</span></td>
                                    <td><span className={getSeverityClass(event.severity)}>{event.severity}</span></td>
                                    <td className="mono">{event.process_name}</td>
                                    <td className="path-cell">{event.details?.fname?.slice(-50) || event.details?.dst_ip || '-'}</td>
                                    <td>
                                        {event.ai_analysis ? (
                                            <span className={`ai-score ${getRisk(event.ai_analysis.risk_score).c}`}>
                                                {event.ai_analysis.risk_score}
                                            </span>
                                        ) : '-'}
                                    </td>
                                </motion.tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
                <div className="history-pagination">
                    <button
                        disabled={page <= 1}
                        onClick={() => setPage(p => Math.max(1, p - 1))}
                    >
                        <ChevronLeft size={16} />Prev
                    </button>
                    <span className="page-info">
                        Page {page} of {totalPages}
                    </span>
                    <button
                        disabled={page >= totalPages}
                        onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                    >
                        Next<ChevronRight size={16} />
                    </button>
                </div>
            )}
        </div>
    )
}

export default History
