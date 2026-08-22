import { useState } from 'react'

/**
 * Format an ISO timestamp to a human-readable local time string.
 */
function formatTime(ts) {
  if (!ts) return ''
  try {
    const d = new Date(ts)
    return d.toLocaleTimeString(undefined, {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    })
  } catch {
    return ts
  }
}

/**
 * Render a single entity field as a styled pill.
 */
function EntityPill({ label, value }) {
  if (!value) return null
  return (
    <span className="entity-pill">
      <span className="entity-pill__label">{label}</span>
      {value}
    </span>
  )
}

export default function EventCard({ event }) {
  const [expanded, setExpanded] = useState(false)

  const severity = event.severity || 'low'
  const entity = event.entity || {}
  const eventType = (event.event_type || 'unknown').replace(/_/g, ' ')

  return (
    <div
      className={`event-card event-card--${severity}`}
      onClick={() => setExpanded((prev) => !prev)}
      role="button"
      tabIndex={0}
      id={`event-${event.event_id}`}
    >
      {/* Header row */}
      <div className="event-card__header">
        <span className={`severity-badge severity-badge--${severity}`}>
          {severity}
        </span>
        <span className="event-card__type">{eventType}</span>
        <span className="event-card__time">{formatTime(event.timestamp)}</span>
      </div>

      {/* Entity pills */}
      <div className="event-card__entities">
        <EntityPill label="IP" value={entity.ip} />
        <EntityPill label="User" value={entity.user} />
        <EntityPill label="Host" value={entity.host} />
        {entity.hash && <EntityPill label="Hash" value={entity.hash.slice(0, 12) + '…'} />}
        {event.source && (
          <span className="entity-pill">
            <span className="entity-pill__label">Source</span>
            {event.source}
          </span>
        )}
      </div>

      {/* Expandable raw data */}
      {expanded && event.raw && (
        <div className="event-card__raw">
          <pre>{JSON.stringify(event.raw, null, 2)}</pre>
        </div>
      )}
    </div>
  )
}
