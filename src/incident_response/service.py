"""Durable response orchestration; storage commits precede external effects."""

from datetime import datetime, timedelta, timezone
import uuid

from .approval import _DISALLOWED_APPROVER_IDENTITIES
from .models import (ActionResult, ApprovalDecision, ApprovalRequest, IncidentPhase,
                     IncidentStateTransition, ResponseAction)
from .state_tracker import ALLOWED_TRANSITIONS


class ResponseError(RuntimeError):
    def __init__(self, message, status=409):
        super().__init__(message)
        self.status = status


class ResponseService:
    def __init__(self, repository, backends, approval_ttl=3600, mode="simulation", clock=None):
        self.repository = repository
        self.backends = {action: backend for backend in backends for action in backend.supported_actions}
        self.approval_ttl = approval_ttl
        self.mode = mode
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.configuration = {backend.name: getattr(backend, "configuration_id", backend.name) for backend in backends}

    def _actor(self, actor):
        actor = (actor or "").strip()
        if actor.lower() in _DISALLOWED_APPROVER_IDENTITIES:
            raise ResponseError("An authenticated human analyst is required", 403)
        return actor

    def _audit(self, entries, incident_id, event, actor, detail):
        entries.append({"incident_id": incident_id, "event": event, "actor": actor,
                        "timestamp": self.clock().isoformat(), "detail": detail})

    def _expire(self, record, entries):
        now = self.clock()
        for request in record["approvals"].values():
            if request["status"] == "pending" and request["expires_at"] and datetime.fromisoformat(request["expires_at"]) <= now:
                request["status"] = "expired"
                self._audit(entries, record["incident_id"], "approval_expired", "system", {"request_id": request["request_id"]})

    def add_plan(self, plan, actor, incident_snapshot=None):
        actor = self._actor(actor)
        incident_id = plan.incident_id
        with self.repository.transaction(incident_id) as (record, audit):
            # Retries and simultaneous requests return the existing plan, not new actions.
            if record["plans"]:
                existing = next(iter(record["plans"].values()))
                return {"plan": existing, "approval_requests": list(record["approvals"].values())}
            state = {"incident_id": incident_id, "phase": "new", "plan_ids": [],
                     "executed_action_ids": [], "transitions": []}
            initial = IncidentStateTransition(incident_id=incident_id, from_phase="new", to_phase="new",
                transitioned_by=actor, transitioned_at=self.clock(), reason="Response plan created")
            state["transitions"].append(initial.model_dump(mode="json"))
            state["plan_ids"].append(plan.plan_id)
            record["state"] = state
            record["execution_mode"] = self.mode
            record["backend_configuration"] = self.configuration
            if incident_snapshot is not None:
                record["incident_snapshot"] = incident_snapshot
            record["plans"][plan.plan_id] = plan.model_dump(mode="json")
            requests = []
            for action in plan.actions:
                if not action.requires_approval:
                    raise ResponseError("Every response action requires approval", 403)
                request = ApprovalRequest(action_id=action.action_id, incident_id=incident_id,
                    plan_id=plan.plan_id, action_type=action.action_type, action_title=action.title,
                    action_description=action.description, target_entity=dict(action.target_entity),
                    requested_at=self.clock(), expires_at=self.clock() + timedelta(seconds=self.approval_ttl))
                record["actions"][action.action_id] = action.model_dump(mode="json")
                record["approvals"][request.request_id] = request.model_dump(mode="json")
                requests.append(request.model_dump(mode="json"))
            self._audit(audit, incident_id, "plan_created", actor, {"plan": plan.model_dump(mode="json"), "approvals": requests})
            return {"plan": plan.model_dump(mode="json"), "approval_requests": requests}

    def decide(self, request_id, approved, actor, reason=""):
        actor = self._actor(actor)
        owner = self.repository.find_owner(request_id)
        if owner is None:
            raise ResponseError("Approval request not found", 404)
        failure = None
        result = None
        with self.repository.transaction(owner) as (record, audit):
            self._expire(record, audit)
            request = record["approvals"].get(request_id)
            if request is None:
                failure = ResponseError("Approval request not found", 404)
            elif request["status"] != "pending":
                failure = ResponseError(f"Approval is {request['status']}", 410 if request["status"] == "expired" else 409)
            else:
                status = "approved" if approved else "rejected"
                decision = ApprovalDecision(request_id=request_id, status=status, decided_by=actor,
                    reason=reason, decided_at=self.clock()).model_dump(mode="json")
                request.update(status=status, decided_by=actor, decided_at=decision["decided_at"], decision_reason=reason)
                record["actions"][request["action_id"]]["execution_status"] = "approved" if approved else "skipped"
                self._audit(audit, owner, f"approval_{status}", actor, {"decision": decision, "action_id": request["action_id"], "target": request["target_entity"]})
                result = {"decision": decision, "request": dict(request)}
        if failure:
            raise failure
        return result

    def workflow(self, incident_id):
        if self.repository.get(incident_id) is None:
            return None
        with self.repository.transaction(incident_id) as (record, audit):
            self._expire(record, audit)
            state = record["state"]
            return {"incident_id": incident_id, "state": state, "execution_mode": self.mode,
                "plan_execution_mode": record.get("execution_mode", "simulation"),
                "configuration_matches": record.get("execution_mode", "simulation") == self.mode and record.get("backend_configuration", self.configuration) == self.configuration,
                "execution_notice": "Configured response backends are simulated; no real system is contained." if self.mode == "simulation" else "Approved actions use configured response integrations.",
                "storage_mode": self.repository.mode,
                "allowed_transitions": sorted(p.value for p in ALLOWED_TRANSITIONS[IncidentPhase(state["phase"])]) if state else [],
                "actions": [{"approval": request, "action": record["actions"].get(request["action_id"]),
                             "result": record["results"].get(request["action_id"])} for request in record["approvals"].values()]}

    def transition(self, incident_id, phase, actor, reason=""):
        actor = self._actor(actor)
        target = IncidentPhase(phase)
        with self.repository.transaction(incident_id) as (record, audit):
            state = record["state"]
            if state is None:
                raise ResponseError("Incident has no response plan", 404)
            previous = IncidentPhase(state["phase"])
            if target not in ALLOWED_TRANSITIONS[previous]:
                raise ResponseError(f"Transition from {previous.value} to {target.value} is not allowed")
            transition = IncidentStateTransition(incident_id=incident_id, from_phase=previous, to_phase=target,
                transitioned_by=actor, reason=reason, transitioned_at=self.clock()).model_dump(mode="json")
            state["phase"] = target.value
            state["transitions"].append(transition)
            self._audit(audit, incident_id, "phase_changed", actor, transition)
            return {"transition": transition, "phase": target.value}

    def execute(self, action_id, actor):
        actor = self._actor(actor)
        owner = self.repository.find_owner(action_id)
        if owner is None:
            raise ResponseError("Action not found", 404)
        claim = str(uuid.uuid4())
        with self.repository.transaction(owner) as (record, audit):
            raw = record["actions"].get(action_id)
            if raw is None:
                raise ResponseError("Action not found", 404)
            if record.get("execution_mode", "simulation") != self.mode or record.get("backend_configuration", self.configuration) != self.configuration:
                raise ResponseError("Execution configuration differs from the reviewed plan. Restore its configuration or create a separately reviewed incident plan.", 409)
            request = next((item for item in record["approvals"].values() if item["action_id"] == action_id), None)
            if not request or request["status"] != "approved" or not request["decided_by"]:
                raise ResponseError("Explicit analyst approval is required", 403)
            action = ResponseAction.model_validate(raw)
            # Bind the approval to the exact action; mutation must require a new approval.
            if not action.requires_approval or request["target_entity"] != action.target_entity or request["action_type"] != action.action_type.value:
                raise ResponseError("Action differs from its approved target or type", 403)
            if action_id in record["results"]:
                return {"result": record["results"][action_id], "action_status": raw["execution_status"]}
            if action_id in record["claims"] or raw["execution_status"] == "executing":
                raise ResponseError("Execution is in progress or its outcome is unknown. Reconcile the backend before taking further action.")
            if raw["execution_status"] != "approved":
                raise ResponseError("Action is not ready for execution")
            backend = self.backends.get(action.action_type)
            if backend is None:
                raise ResponseError("No backend configured for this action", 501)
            record["claims"][action_id] = {"claim": claim, "actor": actor, "started_at": self.clock().isoformat(), "backend": backend.name}
            raw["execution_status"] = "executing"
            self._audit(audit, owner, "execution_claimed", actor, {"action_id": action_id, "claim": claim, "approved_by": request["decided_by"], "backend": backend.name})
        # The durable claim has committed. Never retry the backend after an ambiguous result.
        try:
            result = backend.execute(action)
            if result.action_id != action_id:
                raise ValueError("Backend returned an unexpected action ID")
        except Exception:
            result = ActionResult(action_id=action_id, success=False, backend=backend.name,
                message="Backend did not confirm completion. Inspect its state before planning another action.")
        with self.repository.transaction(owner) as (record, audit):
            if record["claims"].get(action_id, {}).get("claim") != claim:
                raise ResponseError("Execution claim changed; operator reconciliation required")
            status = "completed" if result.success else "failed"
            record["results"][action_id] = result.model_dump(mode="json")
            record["actions"][action_id]["execution_status"] = status
            if result.success and action_id not in record["state"]["executed_action_ids"]:
                record["state"]["executed_action_ids"].append(action_id)
            self._audit(audit, owner, f"execution_{status}", actor, {"claim": claim, "result": result.model_dump(mode="json")})
        return {"result": result.model_dump(mode="json"), "action_status": status}

    def list_approvals(self, incident_id=None, status=None):
        records = [self.repository.get(incident_id)] if incident_id else self.repository.list_records()
        requests = []
        for record in records:
            if not record:
                continue
            workflow = self.workflow(record["incident_id"])
            requests.extend(entry["approval"] for entry in workflow["actions"] if status is None or entry["approval"]["status"] == status)
        return requests

    def stats(self):
        records = self.repository.list_records()
        phases = {}
        effects = {"blocked_ips": set(), "isolated_hosts": set(), "disabled_accounts": set()}
        pending = 0
        for record in records:
            workflow = self.workflow(record["incident_id"])
            if workflow["state"]:
                phase = workflow["state"]["phase"]
                phases[phase] = phases.get(phase, 0) + 1
            for entry in workflow["actions"]:
                pending += entry["approval"]["status"] == "pending"
                if not entry["result"] or not entry["result"]["success"]:
                    continue
                action = entry["action"]
                mapping = {"block_ip": ("blocked_ips", "ip"), "block_egress": ("blocked_ips", "ip"),
                           "isolate_host": ("isolated_hosts", "host"), "disable_account": ("disabled_accounts", "user")}
                if action["action_type"] in mapping:
                    bucket, field = mapping[action["action_type"]]
                    value = action["target_entity"].get(field)
                    if value:
                        effects[bucket].add(value)
        return {"incident_phases": phases, "pending_approvals": pending,
                "total_plans": sum(len(record["plans"]) for record in records),
                "execution_mode": self.mode, "storage_mode": self.repository.mode,
                "effects_notice": "Recorded successful actions; not live verification of containment.",
                **{key: sorted(values) for key, values in effects.items()}}
