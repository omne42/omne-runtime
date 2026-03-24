# Governance and Versioning

## Compatibility Priorities

- safety-relevant behavior should not change silently,
- denial reasons should stay deterministic,
- capability reporting should remain explicit by platform.

## Versioning Strategy

- crate version is API compatibility boundary,
- docs version labels communicate behavior sets,
- releases should update docs when defaults/reasons/platform behavior changes.

## Upgrade Checklist

1. compare `GatewayPolicy` defaults,
2. run `capability` checks across target platforms,
3. validate denial reason handling in orchestrator,
4. validate audit parsing pipeline,
5. roll out with rollback path.
