from src.soc.alerting.manager import AlertManager
from src.soc.correlation.incident_model import Incident


def test_recovered_alert_identity_and_dates_are_stable():
    incident = Incident(title="Synthetic incident", severity="high", event_count=2)
    first = AlertManager().process_incident(incident)
    second = AlertManager().process_incident(Incident.model_validate(incident.model_dump()))
    assert first.alert_id == second.alert_id
    assert first.created_at == second.created_at == incident.created_at
    assert first.updated_at == second.updated_at == incident.updated_at


def test_synchronization_removes_closed_incident_alerts():
    incident = Incident(title="Synthetic incident", severity="high")
    manager = AlertManager()
    manager.synchronize([incident])
    assert manager.alert_count == 1
    incident.status = "closed"
    manager.synchronize([incident])
    assert manager.alert_count == 0
