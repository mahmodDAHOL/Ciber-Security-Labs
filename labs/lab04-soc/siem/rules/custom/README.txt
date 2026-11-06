Write your own detection rules in this folder as .yml files (see tasks 4-6).
The engine reloads this folder automatically every second. No restart needed.

Rule format:

  id: MY-100                 # any unique id
  title: Successful SSH login
  level: medium              # low | medium | high
  mitre: [T1078]             # one or more ATT&CK technique IDs
  match:
    event_type: accepted_login   # failed_login | accepted_login | sudo
    # optional extra equality conditions, e.g.:
    # user: webadmin
  threshold:                 # OPTIONAL - only for "N events in a window" rules
    count: 10
    by: source_ip            # group events by this field
    window: 60               # seconds
