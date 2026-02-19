# Stream-based Anomaly Detector

This project is a security-stream-processor.

## Problem Statement

We have firehose of network logs (JSON). We need a service that:

1. Ingests these logs.
2. Uses an LLM/Heuristic hybrid to flag 'suspicious' activity.
3. Maintains a stateful 'threat score' for different IP addresses.
4. Ensures the logic is explainable.

### Technical hurdle

This is a Python service that processes a stream of 'Event' objects. An Event has a source_ip, endpoint, and payload_size. If an IP hits more than 10 unique endpoints in 1 minute, OR if its cumulative payload_size exceeds a threshold, we need to send that context to an LLM to 'reason' if this is data exfiltration or a false positive.
