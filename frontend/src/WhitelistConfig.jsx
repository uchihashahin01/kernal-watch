import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
    Shield, X, Trash2, Plus, RefreshCw, ChevronLeft, Ban, CheckCircle
} from 'lucide-react'

const BACKEND_URL = 'http://localhost:3000'

function WhitelistConfig({ onBack }) {
    const [entries, setEntries] = useState([])
    const [loading, setLoading] = useState(true)
    const [newProcess, setNewProcess] = useState('')
    const [status, setStatus] = useState(null)

    const fetchWhitelist = async () => {
        setLoading(true)
        try {
            const response = await fetch(`${BACKEND_URL}/api/whitelist`)
            const data = await response.json()
            setEntries(data.entries || [])
        } catch (e) {
            console.error('Failed to fetch whitelist:', e)
        }
        setLoading(false)
    }

    useEffect(() => {
        fetchWhitelist()
    }, [])

    const addToWhitelist = async () => {
        if (!newProcess.trim()) return

        try {
            const response = await fetch(`${BACKEND_URL}/api/actions/whitelist`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    process_name: newProcess.trim(),
                    reason: 'Added manually from Whitelist Config'
                })
            })
            const data = await response.json()
            if (data.success) {
                setStatus({ type: 'success', message: `Added: ${newProcess}` })
                setNewProcess('')
                fetchWhitelist()
            } else {
                setStatus({ type: 'info', message: data.message })
            }
        } catch (e) {
            setStatus({ type: 'error', message: 'Failed to add' })
        }
        setTimeout(() => setStatus(null), 3000)
    }

    const removeFromWhitelist = async (id, processName) => {
        try {
            const response = await fetch(`${BACKEND_URL}/api/whitelist/${id}`, {
                method: 'DELETE'
            })
            const data = await response.json()
            if (data.success) {
                setStatus({ type: 'success', message: `Removed: ${processName}` })
                fetchWhitelist()
            } else {
                setStatus({ type: 'error', message: data.error || 'Failed to remove' })
            }
        } catch (e) {
            setStatus({ type: 'error', message: 'Failed to remove' })
        }
        setTimeout(() => setStatus(null), 3000)
    }

    const formatDate = (ts) => {
        const d = new Date(ts)
        return d.toLocaleDateString() + ' ' + d.toLocaleTimeString()
    }

    return (
        <div className="whitelist-container">
            {/* Header */}
            <div className="whitelist-header">
                <div className="whitelist-title">
                    <button className="back-btn" onClick={onBack}><ChevronLeft size={18} />Back</button>
                    <Shield size={20} />
                    <span>WHITELIST CONFIGURATION</span>
                    <span className="whitelist-count">{entries.length} entries</span>
                </div>
                <div className="whitelist-actions">
                    <button className="refresh-btn" onClick={fetchWhitelist} disabled={loading}>
                        <RefreshCw size={14} className={loading ? 'spinning' : ''} />
                    </button>
                </div>
            </div>

            {/* Status Message */}
            <AnimatePresence>
                {status && (
                    <motion.div
                        className={`whitelist-status-bar ${status.type}`}
                        initial={{ opacity: 0, y: -10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -10 }}
                    >
                        {status.type === 'success' && <CheckCircle size={16} />}
                        {status.message}
                    </motion.div>
                )}
            </AnimatePresence>

            {/* Add New */}
            <div className="whitelist-add">
                <div className="add-input">
                    <input
                        type="text"
                        placeholder="Enter process name or path to whitelist..."
                        value={newProcess}
                        onChange={e => setNewProcess(e.target.value)}
                        onKeyDown={e => e.key === 'Enter' && addToWhitelist()}
                    />
                </div>
                <button className="add-btn" onClick={addToWhitelist} disabled={!newProcess.trim()}>
                    <Plus size={16} />Add to Whitelist
                </button>
            </div>

            {/* Entries List */}
            <div className="whitelist-entries">
                {loading ? (
                    <div className="loading-state"><RefreshCw className="spinning" />Loading...</div>
                ) : entries.length === 0 ? (
                    <div className="empty-state">
                        <Ban size={32} />
                        <span>No whitelist entries</span>
                        <span className="hint">Processes added here will be excluded from threat detection</span>
                    </div>
                ) : (
                    <table className="whitelist-table">
                        <thead>
                            <tr>
                                <th>Process Name</th>
                                <th>Reason</th>
                                <th>Added At</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            {entries.map(entry => (
                                <motion.tr
                                    key={entry.id}
                                    initial={{ opacity: 0 }}
                                    animate={{ opacity: 1 }}
                                    exit={{ opacity: 0 }}
                                >
                                    <td className="process-name">{entry.process_name}</td>
                                    <td className="reason">{entry.reason}</td>
                                    <td className="added-at">{formatDate(entry.added_at)}</td>
                                    <td>
                                        <button
                                            className="remove-btn"
                                            onClick={() => removeFromWhitelist(entry.id, entry.process_name)}
                                            title="Remove from whitelist"
                                        >
                                            <Trash2 size={14} />
                                        </button>
                                    </td>
                                </motion.tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>

            {/* Info Box */}
            <div className="whitelist-info">
                <strong>Note:</strong> Whitelisted processes are excluded from threat detection and AI analysis.
                Removing a process from the whitelist will restore normal threat monitoring for that process.
            </div>
        </div>
    )
}

export default WhitelistConfig
