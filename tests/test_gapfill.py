"""Table-driven boundary coverage for storage.compute_gaps."""

from __future__ import annotations

import pytest

from waf_fu import storage


@pytest.mark.parametrize(
    ("start", "end", "covered", "expected"),
    [
        pytest.param(0, 100, [], [(0, 100)], id="no_coverage"),
        pytest.param(0, 100, [(0, 100)], [], id="exact"),
        pytest.param(0, 100, [(-50, 150)], [], id="containment"),
        pytest.param(0, 100, [(0, 50)], [(50, 100)], id="prefix_covered"),
        pytest.param(0, 100, [(50, 100)], [(0, 50)], id="suffix_covered"),
        pytest.param(0, 100, [(20, 40)], [(0, 20), (40, 100)], id="middle_gap"),
        pytest.param(
            0, 100, [(20, 40), (30, 60)], [(0, 20), (60, 100)], id="overlapping_covered"
        ),
        pytest.param(
            0, 100, [(20, 40), (60, 80)], [(0, 20), (40, 60), (80, 100)], id="two_gaps"
        ),
        pytest.param(
            0, 100, [(40, 60), (20, 40)], [(0, 20), (60, 100)], id="unsorted_input"
        ),
        pytest.param(0, 100, [(200, 300)], [(0, 100)], id="non_overlapping"),
        # The case a single-row containment check would miss: two adjacent
        # fetches jointly cover the requested range, so coverage must be
        # computed as interval subtraction rather than a containment query.
        pytest.param(0, 100, [(0, 40), (40, 100)], [], id="adjacent_union"),
        pytest.param(50, 50, [], [], id="empty_window"),
    ],
)
def test_compute_gaps(start, end, covered, expected):
    assert storage.compute_gaps(start, end, covered) == expected
