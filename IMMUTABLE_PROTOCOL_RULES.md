# Atlas Immutable Protocol Rules

These rules are mandatory and apply to all current and future protocol work in Atlas.

1. **OpenVPN Benchmark (Feature Parity Required)**
   - OpenVPN is the implementation benchmark.
   - Every protocol must reach parity across:
     - DB relations and persistence behavior
     - Global Settings UI and operational controls
     - Runtime online/offline status visibility
     - PBR routing integration
     - Quota enforcement and scheduler integration
     - `install.sh` and `update.sh` lifecycle integration

2. **Absolute Resource Isolation**
   - Protocol resources must never conflict.
   - Every protocol must have isolated:
     - Local IP pools/subnets
     - Ports
     - Routing marks / policy-routing paths
   - Example isolation baseline:
     - OpenVPN: `10.8.0.0/24`
     - WireGuard: `10.9.0.0/24`
     - L2TP/IPsec: `10.10.11.0/24`

3. **Ubuntu 24.04 Compatibility Gate**
   - Production OS baseline is Ubuntu 24.04.
   - Before implementing any protocol, dependencies must be verified as natively supported.
   - If protocol support is deprecated/incompatible (e.g., PPTP/pptpd), implementation must be aborted and escalated immediately.

4. **Zero Prompting Enforcement**
   - Rules 1-3 must be enforced automatically in all future protocol tasks.
   - No reminder from architecture leadership is required for enforcement.
