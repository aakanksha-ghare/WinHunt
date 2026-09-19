# WinHunt
Windows threat hunting and incident analysis platform using Python and Flask.

## Telemetry sources
WinHunt ingests two classes of telemetry that converge on the same normalized event model:

- Synthetic Windows telemetry from the project dataset, normalized through the parser layer
- External EVTX CSV samples from data/external/EVTX-ATTACK-SAMPLES, used as validation/reference data and normalized through the external adapter layer

The detection, correlation, and future query layers should consume the normalized event structure rather than raw source-specific fields. Detection logic remains downstream of ingestion and normalization.
