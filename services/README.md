# Shared Services Boundary

This folder is reserved for cross-runtime service contracts that are shared by the
frontend, backend, bot and worker processes. Implementation code lives inside each
runtime package; shared TypeScript contracts live in `utils/shared-types.ts`.

Production deployments should keep secrets and direct AI/database access inside
`backend/`, `bot/` or worker services only.
