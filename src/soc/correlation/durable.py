"""Correlation interface backed by transactional incident storage."""
from .engine import CorrelationEngine
from ..scoring.calculator import score_incident


class DurableCorrelationEngine:
    def __init__(self, repository, correlation_window_seconds=300, status_provider=None):
        self.repository = repository
        self.correlation_window = correlation_window_seconds
        # API orchestration injects lifecycle statuses; SOC does not import IR internals.
        self.status_provider = status_provider or (lambda: {})

    def _project(self, incidents):
        statuses = self.status_provider()
        for incident in incidents:
            if incident.incident_id in statuses:
                incident.status = statuses[incident.incident_id]
        return incidents

    def process_event(self, event, rule_matches=None):
        def correlate(candidates):
            engine = CorrelationEngine(self.correlation_window)
            engine.restore(self._project(candidates))
            incident = engine.process_event(event, rule_matches)
            if incident is not None:
                incident.risk_score = score_incident(incident)[0]
            return incident
        result = self.repository.correlate(event, self.correlation_window, correlate)
        return self._project([result])[0] if result else None

    def get_incident(self, incident_id):
        incident = self.repository.get(incident_id)
        return self._project([incident])[0] if incident else None

    def list_incidents(self, status=None):
        incidents = self._project(self.repository.list_incidents())
        return [item for item in incidents if status is None or item.status == status]

    @property
    def active_incidents(self):
        return [item for item in self.list_incidents() if item.status in ("open", "investigating")]

    @property
    def active_incident_count(self):
        return len(self.active_incidents)
