## Disk Activity Plus 2026.08.21.6

This is a small usability follow-up to 2026.08.21.5.

### Reset Wake Statistics
- Remove CSRF validation from the reset-history endpoint.
- Keep the endpoint POST-only and require the explicit `reset_history` action.
- Keep the confirmation dialog, shared history lock and atomic replacement behavior.
- This action only clears Disk Activity Plus diagnostic wake history; it does not modify Unraid configuration, storage data or user files.

The stricter CSRF protection added in 2026.08.21.5 caused false token failures on some Unraid WebGUI page contexts and was disproportionate for a diagnostic-only reset action.
