"""Tests for matchedData detection and TUI rendering."""

from __future__ import annotations


def _rule_group_with_matched_data(
    rule_id="detect-body-auth",
    action="COUNT",
    location="BODY",
    condition_type="REGEX",
    matched_data=None,
):
    return [
        {
            "ruleGroupId": "test-acl",
            "nonTerminatingMatchingRules": [
                {
                    "ruleId": rule_id,
                    "action": action,
                    "ruleMatchDetails": [
                        {
                            "conditionType": condition_type,
                            "location": location,
                            "matchedData": matched_data or ["eyJhbGciOiJIUzI1NiJ9"],
                        }
                    ],
                }
            ],
        }
    ]


class TestMatchedDataDetection:
    def test_no_matched_data(self, make_request):
        req = make_request()
        assert not req.has_matched_data
        assert req.matched_data_entries == []

    def test_has_matched_data(self, make_request):
        rgl = _rule_group_with_matched_data()
        req = make_request(rule_group_list=rgl)
        assert req.has_matched_data

    def test_matched_data_entries(self, make_request):
        rgl = _rule_group_with_matched_data(
            rule_id="detect-body-auth",
            location="BODY",
            matched_data=["eyJhbGciOiJIUzI1NiJ9", "client_credentials"],
        )
        req = make_request(rule_group_list=rgl)
        entries = req.matched_data_entries
        assert len(entries) == 1
        assert entries[0]["rule_id"] == "detect-body-auth"
        assert entries[0]["location"] == "BODY"
        assert len(entries[0]["matched_data"]) == 2

    def test_empty_matched_data_ignored(self, make_request):
        rgl = [
            {
                "ruleGroupId": "test-acl",
                "nonTerminatingMatchingRules": [
                    {
                        "ruleId": "count-all",
                        "action": "COUNT",
                        "ruleMatchDetails": [
                            {
                                "conditionType": "SIZE",
                                "location": "BODY",
                                "matchedData": [],
                            }
                        ],
                    }
                ],
            }
        ]
        req = make_request(rule_group_list=rgl)
        assert not req.has_matched_data

    def test_no_rule_match_details(self, make_request):
        rgl = [
            {
                "ruleGroupId": "test-acl",
                "nonTerminatingMatchingRules": [
                    {
                        "ruleId": "count-all",
                        "action": "COUNT",
                    }
                ],
            }
        ]
        req = make_request(rule_group_list=rgl)
        assert not req.has_matched_data

    def test_multiple_rules_with_matched_data(self, make_request):
        rgl = [
            {
                "ruleGroupId": "test-acl",
                "nonTerminatingMatchingRules": [
                    {
                        "ruleId": "detect-body-auth",
                        "action": "COUNT",
                        "ruleMatchDetails": [
                            {
                                "conditionType": "REGEX",
                                "location": "BODY",
                                "matchedData": ["eyJhbGciOiJIUzI1NiJ9"],
                            }
                        ],
                    },
                    {
                        "ruleId": "detect-header-auth",
                        "action": "COUNT",
                        "ruleMatchDetails": [
                            {
                                "conditionType": "REGEX",
                                "location": "HEADER",
                                "matchedData": ["Bearer token123"],
                            }
                        ],
                    },
                ],
            }
        ]
        req = make_request(rule_group_list=rgl)
        entries = req.matched_data_entries
        assert len(entries) == 2
        assert entries[0]["rule_id"] == "detect-body-auth"
        assert entries[1]["rule_id"] == "detect-header-auth"


class TestMatchedDataListLine:
    def test_match_tag_in_list_line(self, make_request):
        rgl = _rule_group_with_matched_data()
        req = make_request(rule_group_list=rgl)
        assert "[MATCH]" in req.list_line()

    def test_no_match_tag_without_matched_data(self, make_request):
        req = make_request()
        assert "[MATCH]" not in req.list_line()


class TestMatchedDataTUIMarker:
    def test_matched_data_marker(self, headless_curses, scripted_stdscr, make_request):
        from waf_fu.tui import WafTUI

        rgl = _rule_group_with_matched_data()
        req = make_request(rule_group_list=rgl)
        tui = WafTUI([req], auth_filter_default=False)
        stdscr = scripted_stdscr(keys=[])
        tui._draw(stdscr)
        list_lines = [l for l in stdscr.drawn if "⚑" in l and "target.example.com" in l]
        assert len(list_lines) >= 1

    def test_no_matched_data_no_marker(
        self, headless_curses, scripted_stdscr, make_request
    ):
        from waf_fu.tui import WafTUI

        req = make_request()
        tui = WafTUI([req], auth_filter_default=False)
        stdscr = scripted_stdscr(keys=[])
        tui._draw(stdscr)
        list_lines = [l for l in stdscr.drawn if "target.example.com" in l]
        assert len(list_lines) >= 1
        for line in list_lines:
            assert "⚑" not in line


class TestMatchedDataDetailView:
    def test_matched_data_section_present(self, make_request):
        from waf_fu.tui import build_detail_lines

        rgl = _rule_group_with_matched_data(matched_data=["eyJhbGciOiJIUzI1NiJ9"])
        req = make_request(rule_group_list=rgl)
        lines = build_detail_lines(req, "curl")
        assert "═══ MATCHED DATA ═══" in lines
        arrow_lines = [l for l in lines if "→" in l]
        assert any("eyJhbGciOiJIUzI1NiJ9" in l for l in arrow_lines)

    def test_no_matched_data_section_without_data(self, make_request):
        from waf_fu.tui import build_detail_lines

        req = make_request()
        lines = build_detail_lines(req, "curl")
        assert "═══ MATCHED DATA ═══" not in lines
