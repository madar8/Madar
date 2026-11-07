# Madar — Employee Self-Service Rebuild

## Scope (phase 1)
- Replace the existing HR administration experience with an employee-only self-service portal, visually aligned with Odoo.
- Employee navigation: My Account, Employee Information, Services, My Requests, Settings.
- No local employee directory, payroll administration, recruiting, or manager/HR administration screens.
- Odoo remains untouched. No Odoo writes, schema changes, or synchronization in this phase.
- Employee profile display must ultimately read from Odoo; do not fabricate profiles or silently substitute local employee records.
- Phase 2, separately: integrate requests with Odoo.

## Security gate
- National ID plus its last four digits is predictable and cannot safely authenticate real employees. Use only synthetic test identities in an isolated development preview until a stronger login mechanism is implemented.
- Do not delete production employee records, secrets, or databases as part of source-code replacement.

## Implementation sequence
1. Inventory existing routes and storage boundaries.
2. Build an Odoo-style employee-only shell and self-service screens.
3. Disable administrative UI and local employee-data operations.
4. Add read-only Odoo profile adapter once connection parameters are available, without changing Odoo.
5. Test with synthetic data before any production deployment.
