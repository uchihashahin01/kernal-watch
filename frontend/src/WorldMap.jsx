import { useState, memo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
    ComposableMap,
    Geographies,
    Geography,
    Marker,
    Line,
    ZoomableGroup
} from 'react-simple-maps'
import { Globe, AlertTriangle, Wifi, ZoomIn, ZoomOut, RotateCcw } from 'lucide-react'

// World GeoJSON URL (low-res for performance)
const GEO_URL = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json"

// Your machine's approximate location (customize this)
const HOME_COORDS = [-77.0, 38.9] // [lon, lat] Washington DC

// High-risk countries for visual indicators
const HIGH_RISK_COUNTRIES = ['RU', 'CN', 'KP', 'IR', 'SY']

const WorldMap = memo(function WorldMap({ connections = [], onConnectionClick }) {
    const [hoveredCountry, setHoveredCountry] = useState(null)
    const [zoom, setZoom] = useState(1)
    const [center, setCenter] = useState([0, 20])

    // Get unique countries from connections
    const countryCounts = connections.reduce((acc, conn) => {
        acc[conn.country] = (acc[conn.country] || 0) + 1
        return acc
    }, {})

    const handleZoomIn = () => setZoom(prev => Math.min(prev * 1.5, 8))
    const handleZoomOut = () => setZoom(prev => Math.max(prev / 1.5, 1))
    const handleReset = () => { setZoom(1); setCenter([0, 20]) }

    return (
        <div className="world-map-container">
            <div className="map-header">
                <Globe size={14} />
                <span>GLOBAL THREAT MAP</span>
                <span className="connection-count">{connections.length} connections</span>
                <div className="zoom-controls">
                    <button onClick={handleZoomIn} title="Zoom In"><ZoomIn size={14} /></button>
                    <button onClick={handleZoomOut} title="Zoom Out"><ZoomOut size={14} /></button>
                    <button onClick={handleReset} title="Reset"><RotateCcw size={14} /></button>
                </div>
            </div>

            <div className="map-wrapper">
                <ComposableMap
                    projection="geoMercator"
                    projectionConfig={{
                        scale: 100
                    }}
                >
                    <ZoomableGroup
                        zoom={zoom}
                        center={center}
                        onMoveEnd={({ coordinates, zoom }) => {
                            setCenter(coordinates)
                            setZoom(zoom)
                        }}
                    >
                        {/* Countries */}
                        <Geographies geography={GEO_URL}>
                            {({ geographies }) =>
                                geographies.map((geo) => {
                                    const countryCode = geo.properties.ISO_A2
                                    const isHighRisk = HIGH_RISK_COUNTRIES.includes(countryCode)
                                    const hasConnections = countryCounts[countryCode] > 0

                                    return (
                                        <Geography
                                            key={geo.rsmKey}
                                            geography={geo}
                                            onMouseEnter={() => setHoveredCountry(geo.properties.NAME)}
                                            onMouseLeave={() => setHoveredCountry(null)}
                                            style={{
                                                default: {
                                                    fill: isHighRisk ? '#3d1f1f' : hasConnections ? '#1a3a2a' : '#1a1f2e',
                                                    stroke: '#2a3f5f',
                                                    strokeWidth: 0.3,
                                                    outline: 'none'
                                                },
                                                hover: {
                                                    fill: isHighRisk ? '#5a2a2a' : '#2a4a3a',
                                                    stroke: '#4a6f9f',
                                                    strokeWidth: 0.5,
                                                    outline: 'none'
                                                }
                                            }}
                                        />
                                    )
                                })
                            }
                        </Geographies>

                        {/* Connection Lines */}
                        <AnimatePresence>
                            {connections.map((conn) => (
                                <motion.g key={conn.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                                    <Line
                                        from={HOME_COORDS}
                                        to={[conn.lon, conn.lat]}
                                        stroke={conn.is_threat ? '#ff3366' : HIGH_RISK_COUNTRIES.includes(conn.country) ? '#ffaa00' : '#00ff88'}
                                        strokeWidth={conn.is_threat ? 1.5 : 0.8}
                                        strokeLinecap="round"
                                        strokeDasharray={conn.is_threat ? "none" : "3 2"}
                                        className="connection-line"
                                    />
                                </motion.g>
                            ))}
                        </AnimatePresence>

                        {/* Home Marker */}
                        <Marker coordinates={HOME_COORDS}>
                            <circle r={4} fill="#00ff88" className="pulse-marker" />
                            <circle r={2} fill="#ffffff" />
                        </Marker>

                        {/* Destination Markers */}
                        {connections.map((conn) => (
                            <Marker
                                key={conn.id}
                                coordinates={[conn.lon, conn.lat]}
                                onClick={() => onConnectionClick && onConnectionClick(conn)}
                            >
                                <motion.circle
                                    r={conn.is_threat ? 4 : 2.5}
                                    fill={conn.is_threat ? '#ff3366' : HIGH_RISK_COUNTRIES.includes(conn.country) ? '#ffaa00' : '#00aaff'}
                                    initial={{ scale: 0 }}
                                    animate={{ scale: 1 }}
                                    className={conn.is_threat ? 'threat-marker' : ''}
                                    style={{ cursor: 'pointer' }}
                                />
                            </Marker>
                        ))}
                    </ZoomableGroup>
                </ComposableMap>

                {/* Hover Tooltip */}
                {hoveredCountry && (
                    <div className="map-tooltip">
                        {hoveredCountry}
                    </div>
                )}
            </div>

            {/* Legend + Connection List Row */}
            <div className="map-footer">
                <div className="map-legend">
                    <div className="legend-item"><span className="dot home"></span><span>You</span></div>
                    <div className="legend-item"><span className="dot safe"></span><span>Normal</span></div>
                    <div className="legend-item"><span className="dot warning"></span><span>High-Risk</span></div>
                    <div className="legend-item"><span className="dot threat"></span><span>Threat</span></div>
                </div>

                {/* Compact Connections */}
                <div className="connection-badges">
                    {connections.slice(0, 3).map((conn) => (
                        <div
                            key={conn.id}
                            className={`conn-badge ${conn.is_threat ? 'threat' : ''} ${HIGH_RISK_COUNTRIES.includes(conn.country) ? 'warning' : ''}`}
                            onClick={() => onConnectionClick && onConnectionClick(conn)}
                            title={`${conn.dst_ip} - ${conn.comm}`}
                        >
                            {conn.is_threat ? <AlertTriangle size={10} /> : <Wifi size={10} />}
                            <span>{conn.country}</span>
                        </div>
                    ))}
                    {connections.length === 0 && (
                        <span className="no-conn">Monitoring...</span>
                    )}
                    {connections.length > 3 && (
                        <span className="more-conn">+{connections.length - 3} more</span>
                    )}
                </div>
            </div>
        </div>
    )
})

export default WorldMap
