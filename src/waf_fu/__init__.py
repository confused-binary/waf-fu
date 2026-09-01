"""
AWS WAF v2 Log Browser & Replayer
=================================
Browse, filter, replay, and export AWS WAF v2 logs. Pulls logs from
CloudWatch, S3, and the WAF sampling API (with SQLite caching), displays
them in a split-pane terminal UI with auth detection and YAML-based
filtering, and replays requests through Firefox, Chrome, or curl with
full header/cookie/body fidelity. Supports batch export to curl, JSON,
and HAR.

Usage:
    waf-fu                                  Interactive TUI with log group picker
    waf-fu --log-group aws-waf-logs-my-acl  Specific CloudWatch log group
    waf-fu --s3-bucket aws-waf-logs-bucket  Specific S3 WAF log bucket
    waf-fu --start 4h --action BLOCK        Last 4 hours, blocked only
    waf-fu --inventory                      Discover and fetch all sources
    waf-fu --db-only                        Offline: cached records only
    waf-fu --mode batch-curl -o out.sh      Export as curl commands
    waf-fu --export logs.json               Export cached logs to JSON

Keys (TUI):
  AWS
    l               Switch log group
    r               Switch AWS region
    F5              Refresh logs
    F2              Toggle auto-refresh
    F3              Set auto-refresh interval

  View
    v               Cycle view (detail / json / headers)
    S               Cycle source (merged / cwl / s3 / waf)
    m               Cycle replay mode (firefox / chrome / curl)

  Search & Filter
    t               Toggle auth filter
    b               Toggle hide BLOCK entries
    w / W           Set start / end time window
    o / O           Cycle sort field / toggle sort direction
    f               Filter rules manager
    F               Clear all filters, rules & selection

  Selection & Replay
    Space           Toggle selection
    a               Select all / deselect all
    Enter           Replay selected (or cursor)
    e               Edit request before replay

  Navigation
    Up/Down         Move cursor
    PgUp/PgDn       Jump 10 entries
    Home/End         First / last entry
    [ / ]           Scroll detail pane up / down
    ; / '           Scroll detail pane left / right
    Tab/Shift+Tab   Jump to next / previous section

  Other
    h / ?           Help overlay
    q               Quit
"""

__version__ = "0.1.1"
