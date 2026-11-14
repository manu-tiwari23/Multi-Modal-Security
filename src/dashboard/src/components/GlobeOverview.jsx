import { useEffect, useRef, useMemo } from 'react'
import '../globe.css'

// Pre-configured distinct coordinate locations for connected network systems on the 3D globe
const SYSTEM_SLOTS = [
  { lat: 25, lon: -40 },   // System 1 (e.g. prod-web-01, upper left)
  { lat: -15, lon: 55 },   // System 2 (e.g. db-cluster-01, lower right)
  { lat: 42, lon: 65 },    // System 3 (e.g. auth-gateway, upper right)
  { lat: -25, lon: -75 },  // System 4 (e.g. firewall-edge, lower left)
  { lat: 15, lon: 135 },   // System 5 (e.g. honeypot-trap, far right)
  { lat: 52, lon: -125 },  // System 6 (e.g. k8s-cluster, top left)
  { lat: -38, lon: 115 },  // System 7 (e.g. backup-node, bottom right)
  { lat: 0, lon: 10 },     // System 8 (e.g. core-router, center)
]

export default function GlobeOverview({
  connected,
  alertCount,
  alerts = [],
  events = [],
  customNodes = [],
  onAddDemoNode,
  onResetNodes,
  onInvestigate,
  onCopilot,
  canUseCopilot,
}) {
  const canvasRef = useRef(null)
  const rotationY = useRef(0.8)
  const rotationX = useRef(0.25)
  const dragging = useRef(null)
  const lastMousePos = useRef({ x: 0, y: 0 })
  const shockwaves = useRef([])

  // Discover connected network systems dynamically or through user additions
  const connectedSystems = useMemo(() => {
    const map = new Map()

    // 1. Systems in alerts
    for (const alert of alerts) {
      const host = alert.primary_entity?.host
      const ip = alert.primary_entity?.ip
      const key = host || ip
      if (!key) continue
      if (!map.has(key)) {
        map.set(key, {
          id: key,
          host: host || key,
          ip: ip || 'Unknown',
          role: 'Observed system',
          alerts: [],
          eventsCount: 0,
          status: 'normal',
        })
      }
      const item = map.get(key)
      item.alerts.push(alert)
      const sev = (alert.severity || alert.priority || '').toLowerCase()
      if (sev.includes('crit') || sev.includes('p1') || (alert.risk_score || 0) >= 70) {
        item.status = 'critical'
      } else if (
        item.status !== 'critical' &&
        (sev.includes('high') || sev.includes('medium') || (alert.risk_score || 0) >= 30)
      ) {
        item.status = 'mild'
      }
    }

    // 2. Systems in events
    for (const ev of events) {
      const host = ev.entity?.host
      if (!host) continue
      if (!map.has(host)) {
        const simulated = Boolean(ev.raw?.simulated || ev.enrichment?.simulation_scenario === 'node_activity')
        map.set(host, {
          id: host,
          host: host,
          ip: ev.entity?.ip || 'Unknown',
          role: simulated ? 'Synthetic telemetry node' : 'Observed system',
          alerts: [],
          eventsCount: 0,
          status: simulated ? 'demo' : 'normal',
          simulated,
        })
      }
      const item = map.get(host)
      item.eventsCount += 1
      if ((!item.ip || item.ip === 'Unknown') && ev.entity?.ip) item.ip = ev.entity.ip
      const sev = (ev.severity || '').toLowerCase()
      if (!item.simulated && item.status !== 'critical' && (sev === 'high' || sev === 'medium')) {
        item.status = 'mild'
      }
    }

    // 3. Append clearly marked visual-only nodes added by the analyst.
    for (const cn of customNodes) {
      if (!map.has(cn.id)) {
        map.set(cn.id, {
          ...cn,
          status: 'demo',
        })
      } else {
        const existing = map.get(cn.id)
        Object.assign(existing, cn, {
          eventsCount: Math.max(existing.eventsCount || 0, cn.eventsCount || 0),
          status: existing.status === 'critical' || existing.status === 'mild' ? existing.status : 'demo',
          simulated: true,
        })
      }
    }

    const items = Array.from(map.values())
    return items.map((sys, idx) => {
      const slot = SYSTEM_SLOTS[idx] || {
        lat: Math.asin(1 - 2 * (idx + 0.5) / Math.max(items.length, 1)) * (180 / Math.PI),
        lon: ((idx * 137.508) % 360) - 180,
      }
      const phi = (90 - slot.lat) * (Math.PI / 180)
      const theta = (slot.lon + 180) * (Math.PI / 180)
      return {
        ...sys,
        lat: slot.lat,
        lon: slot.lon,
        x: Math.sin(phi) * Math.cos(theta),
        y: Math.cos(phi),
        z: Math.sin(phi) * Math.sin(theta),
      }
    })
  }, [alerts, events, customNodes])

  // Overall posture based on system statuses
  const highestSeverity = useMemo(() => {
    if (connectedSystems.some((s) => s.status === 'critical')) return 'critical'
    if (connectedSystems.some((s) => s.status === 'mild')) return 'high'
    return 'normal'
  }, [connectedSystems])

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    let animId
    const isReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches

    // Initialize shockwaves on attacked systems
    shockwaves.current = []
    connectedSystems.forEach((sys) => {
      if (sys.status === 'critical' || sys.status === 'mild') {
        const phi = (90 - sys.lat) * (Math.PI / 180)
        const theta = (sys.lon + 180) * (Math.PI / 180)
        shockwaves.current.push({
          lat: sys.lat * (Math.PI / 180),
          lon: sys.lon * (Math.PI / 180),
          sysId: sys.id,
          radius: 0,
          maxRadius: sys.status === 'critical' ? 36 : 24,
          alpha: 1,
          speed: sys.status === 'critical' ? 0.8 : 0.5,
          color: sys.status === 'critical' ? '#ef4444' : '#f97316',
        })
      }
    })

    const render = () => {
      const rect = canvas.getBoundingClientRect()
      const dpr = window.devicePixelRatio || 1
      if (canvas.width !== Math.round(rect.width * dpr) || canvas.height !== Math.round(rect.height * dpr)) {
        canvas.width = Math.round(rect.width * dpr)
        canvas.height = Math.round(rect.height * dpr)
      }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      const w = rect.width
      const h = rect.height
      const globeRadius = Math.min(w * 0.35, h * 0.42, 210)
      const centerX = w * 0.5
      const centerY = h * 0.52

      ctx.clearRect(0, 0, w, h)

      // Auto-rotation when not dragging
      if (!isReduced && !dragging.current) {
        rotationY.current += 0.003
      }

      // 1. Atmosphere Ambient Glow
      const atmosGrad = ctx.createRadialGradient(
        centerX,
        centerY,
        globeRadius * 0.85,
        centerX,
        centerY,
        globeRadius * 1.35
      )
      atmosGrad.addColorStop(0, 'rgba(56, 189, 248, 0.12)')
      atmosGrad.addColorStop(0.7, 'rgba(14, 116, 144, 0.05)')
      atmosGrad.addColorStop(1, 'rgba(0,0,0,0)')
      ctx.fillStyle = atmosGrad
      ctx.fillRect(0, 0, w, h)

      // 2. Translucent Cyber Planet Sphere Body
      ctx.beginPath()
      ctx.arc(centerX, centerY, globeRadius, 0, Math.PI * 2)
      const sphereFill = ctx.createRadialGradient(
        centerX - globeRadius * 0.35,
        centerY - globeRadius * 0.35,
        globeRadius * 0.1,
        centerX,
        centerY,
        globeRadius
      )
      sphereFill.addColorStop(0, '#0a1926')
      sphereFill.addColorStop(0.7, '#05101a')
      sphereFill.addColorStop(1, '#02070e')
      ctx.fillStyle = sphereFill
      ctx.fill()
      ctx.strokeStyle = 'rgba(56, 189, 248, 0.28)'
      ctx.lineWidth = 1.4
      ctx.stroke()

      // 3. 3D Rotation Projection
      const cosX = Math.cos(rotationX.current)
      const sinX = Math.sin(rotationX.current)
      const cosY = Math.cos(rotationY.current)
      const sinY = Math.sin(rotationY.current)

      const project = (x, y, z) => {
        const x1 = x * cosY - z * sinY
        const z1 = z * cosY + x * sinY
        const y2 = y * cosX - z1 * sinX
        const z2 = z1 * cosX + y * sinX
        return {
          px: centerX + x1 * globeRadius,
          py: centerY - y2 * globeRadius,
          pz: z2,
        }
      }

      // 4. Latitude Wireframe Graticules
      ctx.lineWidth = 0.6
      for (let latDeg = -60; latDeg <= 60; latDeg += 30) {
        const phi = (90 - latDeg) * (Math.PI / 180)
        const ringRad = Math.sin(phi)
        const ringY = Math.cos(phi)
        ctx.beginPath()
        let started = false
        for (let a = 0; a <= Math.PI * 2 + 0.1; a += 0.15) {
          const pt = project(ringRad * Math.cos(a), ringY, ringRad * Math.sin(a))
          if (pt.pz > -0.1) {
            if (!started) {
              ctx.moveTo(pt.px, pt.py)
              started = true
            } else {
              ctx.lineTo(pt.px, pt.py)
            }
          } else {
            started = false
          }
        }
        ctx.strokeStyle = latDeg === 0 ? 'rgba(56, 189, 248, 0.24)' : 'rgba(56, 189, 248, 0.08)'
        ctx.stroke()
      }

      // Longitude Wireframe Meridians (every 30 degrees)
      for (let lonDeg = 0; lonDeg < 180; lonDeg += 30) {
        const rad = lonDeg * (Math.PI / 180)
        ctx.beginPath()
        let started = false
        for (let a = 0; a <= Math.PI * 2 + 0.1; a += 0.15) {
          const mx = Math.sin(a) * Math.cos(rad)
          const my = Math.cos(a)
          const mz = Math.sin(a) * Math.sin(rad)
          const pt = project(mx, my, mz)
          if (pt.pz > -0.1) {
            if (!started) {
              ctx.moveTo(pt.px, pt.py)
              started = true
            } else {
              ctx.lineTo(pt.px, pt.py)
            }
          } else {
            started = false
          }
        }
        ctx.strokeStyle = 'rgba(56, 189, 248, 0.08)'
        ctx.stroke()
      }

      // 5. Inter-System Network Mesh Links (arcs between connected systems if >= 2)
      if (connectedSystems.length >= 2) {
        for (let i = 0; i < connectedSystems.length; i++) {
          for (let j = i + 1; j < connectedSystems.length; j++) {
            const s1 = connectedSystems[i]
            const s2 = connectedSystems[j]
            const p1 = project(s1.x, s1.y, s1.z)
            const p2 = project(s2.x, s2.y, s2.z)

            if (p1.pz > -0.1 && p2.pz > -0.1) {
              ctx.beginPath()
              ctx.moveTo(p1.px, p1.py)
              // Arc quadratic control point towards globe center
              const midX = (p1.px + p2.px) * 0.5
              const midY = (p1.py + p2.py) * 0.5
              ctx.quadraticCurveTo(midX, midY, p2.px, p2.py)

              const isHostile = s1.status === 'critical' || s2.status === 'critical'
              ctx.strokeStyle = isHostile
                ? 'rgba(239, 68, 68, 0.22)'
                : 'rgba(56, 189, 248, 0.16)'
              ctx.lineWidth = 1
              ctx.setLineDash([3, 4])
              ctx.stroke()
              ctx.setLineDash([])

              // Animated packet dot traversing the link
              const t = (Date.now() / 1800 + i * 0.3) % 1
              const pktX = p1.px + (p2.px - p1.px) * t
              const pktY = p1.py + (p2.py - p1.py) * t
              ctx.beginPath()
              ctx.arc(pktX, pktY, 1.8, 0, Math.PI * 2)
              ctx.fillStyle = isHostile ? '#ef4444' : '#38bdf8'
              ctx.fill()
            }
          }
        }
      }

      // 6. Connected System Nodes (THE DOTS: 1 system = 1 dot, 2 systems = 2 dots)
      connectedSystems.forEach((sys, idx) => {
        const p = project(sys.x, sys.y, sys.z)
        if (p.pz < -0.2) return // Behind globe

        const isFront = p.pz >= 0
        const alpha = isFront ? 1.0 : Math.max(0.3, 1.0 + p.pz * 2)

        // Color based on exact system health: Green (normal) / Orange (mild) / Red (attack)
        let nodeColor = '#22c55e'
        let glowColor = 'rgba(34, 197, 94,'
        if (sys.status === 'critical') {
          nodeColor = '#ef4444'
          glowColor = 'rgba(239, 68, 68,'
        } else if (sys.status === 'mild') {
          nodeColor = '#f97316'
          glowColor = 'rgba(249, 115, 22,'
        }

        // Animated pulsing aura around node
        const pulseTime = Date.now() / 350 + idx
        const pulseR = 8 + Math.sin(pulseTime) * 4
        const pulseAlpha = Math.max(0.15, (Math.cos(pulseTime) + 1) / 3)

        ctx.strokeStyle = `${glowColor} ${pulseAlpha * alpha})`
        ctx.lineWidth = 1.8
        ctx.beginPath()
        ctx.arc(p.px, p.py, pulseR, 0, Math.PI * 2)
        ctx.stroke()

        // Core system dot
        ctx.fillStyle = `${glowColor} ${alpha})`
        ctx.beginPath()
        ctx.arc(p.px, p.py, 5.5, 0, Math.PI * 2)
        ctx.fill()

        // Center bright LED pin
        ctx.fillStyle = '#ffffff'
        ctx.beginPath()
        ctx.arc(p.px, p.py, 2, 0, Math.PI * 2)
        ctx.fill()

        // Draw leader line and HUD label tag for front-facing nodes
        if (isFront) {
          const leaderX = p.px + 22
          const leaderY = p.py - 22

          ctx.beginPath()
          ctx.moveTo(p.px, p.py)
          ctx.lineTo(leaderX, leaderY)
          ctx.lineTo(leaderX + 65, leaderY)
          ctx.strokeStyle = `${glowColor} 0.5)`
          ctx.lineWidth = 1
          ctx.stroke()

          // HUD Pill Box
          const textHost = sys.host
          const textIp = sys.ip && sys.ip !== 'Unknown' ? sys.ip : 'IP unavailable'
          const textStatus =
            sys.status === 'critical'
              ? '● CRITICAL ATTACK'
              : sys.status === 'mild'
              ? '● MILD ACTIVITY'
              : sys.status === 'demo'
              ? '◇ SIMULATED'
              : '● SECURE · ONLINE'

          ctx.font = 'bold 10px monospace'
          const hostW = ctx.measureText(textHost).width
          ctx.font = '9px monospace'
          const ipW = ctx.measureText(textIp).width
          const statW = ctx.measureText(textStatus).width
          const boxW = Math.max(hostW, ipW, statW) + 14

          ctx.fillStyle = 'rgba(11, 20, 30, 0.92)'
          ctx.strokeStyle = `${glowColor} 0.65)`
          ctx.lineWidth = 1
          ctx.beginPath()
          ctx.roundRect(leaderX, leaderY - 36, boxW, 34, 5)
          ctx.fill()
          ctx.stroke()

          // Text labels
          ctx.fillStyle = '#f8fafc'
          ctx.font = 'bold 9.5px monospace'
          ctx.fillText(textHost, leaderX + 7, leaderY - 24)

          ctx.fillStyle = '#94a3b8'
          ctx.font = '8.5px monospace'
          ctx.fillText(textIp, leaderX + 7, leaderY - 14)

          ctx.fillStyle = nodeColor
          ctx.font = '8.5px monospace'
          ctx.fillText(textStatus, leaderX + 7, leaderY - 4)
        }
      })

      // 7. Ground Shockwaves expanding on Attacked Systems
      for (let s = shockwaves.current.length - 1; s >= 0; s--) {
        const sw = shockwaves.current[s]
        const phi = Math.PI / 2 - sw.lat
        const theta = sw.lon + Math.PI
        const sx = Math.sin(phi) * Math.cos(theta)
        const sy = Math.cos(phi)
        const sz = Math.sin(phi) * Math.sin(theta)
        const sp = project(sx, sy, sz)

        if (sp.pz > 0) {
          ctx.strokeStyle = sw.color
          ctx.lineWidth = 1.6
          ctx.beginPath()
          ctx.arc(sp.px, sp.py, sw.radius, 0, Math.PI * 2)
          ctx.stroke()
        }

        sw.radius += sw.speed
        sw.alpha -= 0.025
        if (sw.radius > sw.maxRadius || sw.alpha <= 0) {
          sw.radius = 0
          sw.alpha = 1
        }
      }

      animId = requestAnimationFrame(render)
    }

    render()
    return () => cancelAnimationFrame(animId)
  }, [connectedSystems])

  return (
    <section className={`globe-overview status-${highestSeverity}`} aria-labelledby="globe-title">
      {/* Heading */}
      <div className="globe-heading">
        <div className="globe-eyebrow">
          <span className={`pulse-led ${highestSeverity}`} />
          NETWORK TOPOLOGY · {connectedSystems.filter((system) => !system.simulated).length} OBSERVED · {customNodes.length} SIMULATED
        </div>
        <h2 id="globe-title">
          {highestSeverity === 'critical'
            ? 'High-priority detections'
            : highestSeverity === 'high'
            ? 'Activity to review'
            : 'Observed systems'}
        </h2>
        <span className="globe-subtitle">
          {connected ? 'Symbolic positions and links · not geographic or measured network traffic' : 'Gateway offline · showing last available snapshot'}
        </span>
      </div>

      {/* Top HUD Overlay: Node Counter, Switcher, and System Status Chips */}
      <div className="globe-hud-overlay">
        {/* Node Addition Controls */}
        <div className="systems-count-selector">
          <button
            className="node-toggle-btn active"
            onClick={onAddDemoNode}
            title="Add a simulated node to preview the topology layout"
          >
            + Demo node
          </button>
          {customNodes.length > 0 && (
            <button
              className="node-toggle-btn text-slate-400"
              onClick={onResetNodes}
              title="Reset added nodes to baseline"
            >
              Reset
            </button>
          )}
        </div>

        {/* System Health Badges */}
        <div className="sector-defense-matrix">
          {connectedSystems.map((sys) => {
            const dot = sys.status === 'critical' ? '🔴' : sys.status === 'mild' ? '🟠' : sys.status === 'demo' ? '◇' : '🟢'
            const colorClass =
              sys.status === 'critical'
                ? 'sec-critical'
                : sys.status === 'mild'
                ? 'sec-mild'
                : sys.status === 'demo' ? 'sec-demo' : 'sec-normal'
            return (
              <div key={sys.id} className={`sector-pill ${colorClass}`}>
                <span>{dot}</span>
                <span className="sector-pill__identity"><strong>{sys.host}</strong><code>{sys.ip || 'IP unavailable'}</code></span>
                <small>{sys.status === 'normal' ? 'NO MATCHED ALERT' : sys.status === 'demo' ? 'SIMULATED' : sys.status.toUpperCase()}</small>
              </div>
            )
          })}
        </div>

        <div className="globe-actions">
          <button className="globe-btn globe-btn-primary" onClick={onInvestigate}>
            Investigate Incidents <span>↗</span>
          </button>
          {canUseCopilot && (
            <button className="globe-btn" onClick={onCopilot}>
              ✦ Copilot
            </button>
          )}
        </div>
      </div>

      {/* 3D Canvas */}
      <canvas
        ref={canvasRef}
        aria-label="3D Connected Network Systems Globe"
        onPointerDown={(e) => {
          dragging.current = true
          lastMousePos.current = { x: e.clientX, y: e.clientY }
          e.currentTarget.setPointerCapture(e.pointerId)
        }}
        onPointerMove={(e) => {
          if (dragging.current) {
            const dx = e.clientX - lastMousePos.current.x
            const dy = e.clientY - lastMousePos.current.y
            // Inverted dx so globe moves in exact direction mouse is dragged
            rotationY.current -= dx * 0.007
            rotationX.current = Math.max(-0.9, Math.min(0.9, rotationX.current + dy * 0.005))
            lastMousePos.current = { x: e.clientX, y: e.clientY }
          }
        }}
        onPointerUp={() => {
          dragging.current = false
        }}
        onPointerCancel={() => {
          dragging.current = false
        }}
      />

      {/* Live Stream Ticker */}
      <div className="globe-live-ticker">
        <div className="ticker-label">Network Systems Status Stream</div>
        <div className="ticker-val">
          {connectedSystems.length
            ? `${connectedSystems.filter((system) => !system.simulated).length} observed · ${customNodes.length} simulated · ${alerts.length} active alerts · Drag to rotate`
            : 'No host telemetry yet. Run a simulation or connect a log source.'}
        </div>
      </div>
    </section>
  )
}
