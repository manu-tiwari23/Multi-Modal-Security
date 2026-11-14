export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

export function makeActivityBuckets(events = []) {
  const now = Date.now()
  const windowMs = 24 * 60 * 60 * 1000
  const starts = now - windowMs
  const bucketSize = windowMs / 8
  const buckets = Array.from({ length: 8 }, (_, index) => ({
    label: new Date(starts + index * bucketSize).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    events: 0,
    critical: 0,
    high: 0,
  }))

  for (const event of events) {
    const timestamp = new Date(event.timestamp || event.created_at || NaN).getTime()
    if (!Number.isFinite(timestamp) || timestamp < starts || timestamp > now) continue
    const index = Math.min(7, Math.max(0, Math.floor((timestamp - starts) / bucketSize)))
    buckets[index].events += 1
    const severity = (event.severity || '').toUpperCase()
    if (severity === 'CRITICAL' || severity === 'P1') buckets[index].critical += 1
    if (severity === 'HIGH' || severity === 'P2') buckets[index].high += 1
  }
  return buckets
}

export function makeSeverityData(events = []) {
  return SEVERITIES.map((severity) => ({
    severity,
    count: events.filter((event) => (event.severity || '').toUpperCase() === severity).length,
  }))
}

export function makeSourceData(events = []) {
  const labels = [
    ['soc', 'SOC'],
    ['phishing', 'Phishing'],
    ['honeypot', 'Honeypot'],
    ['forensics', 'Forensics'],
    ['threat_intel', 'Intelligence'],
  ]
  return labels.map(([source, label]) => ({
    source,
    label,
    count: events.filter((event) => event.source === source).length,
  }))
}
