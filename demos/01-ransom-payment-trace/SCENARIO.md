# Scenario: Ransom payment traced through mixer to sanctioned exchange

Funds moved from the LockBit-affiliated wallet through a mixer (Tornado-style hops) to a sanctioned exchange.

## Expected findings

- CT-MIXER-001 × 2
- CT-SDN-001 (critical) at endpoint

## Why this matters

Refer to FinCEN. Mixer use + sanctioned destination = FinCEN reportable.
