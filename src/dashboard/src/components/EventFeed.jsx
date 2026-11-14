import EventCard from './EventCard.jsx'

export default function EventFeed({ events }) {
  return (
    <section id="event-feed" aria-labelledby="event-feed-title">
      <div className="feed__header">
        <div>
          <p className="eyebrow">TELEMETRY</p>
          <h2 id="event-feed-title" className="feed__title">Event stream</h2>
        </div>
        <span className="feed__count">
          {events.length} event{events.length !== 1 ? 's' : ''}
        </span>
      </div>

      {events.length === 0 ? (
        <div className="feed__empty">
          <div className="feed__empty-icon">📡</div>
          <p>Waiting for events…</p>
          <p style={{ marginTop: '0.5rem', fontSize: '0.78rem' }}>
            Start the ingestion service and generate some logs to see them here.
          </p>
        </div>
      ) : (
        <div className="feed__list">
          {events.map((event, idx) => (
            <EventCard key={event.event_id || idx} event={event} />
          ))}
        </div>
      )}
    </section>
  )
}
