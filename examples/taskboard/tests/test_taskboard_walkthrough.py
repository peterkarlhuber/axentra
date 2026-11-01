"""The scripted walkthrough (examples/taskboard/walkthrough.py) passes against an in-process app."""

from __future__ import annotations

import pytest
import walkthrough

pytestmark = pytest.mark.postgres


def test_walkthrough_runs_end_to_end(board, new_client):
    lines: list[str] = []
    result = walkthrough.run(new_client, suffix="t1", log=lines.append)
    assert len(lines) >= 8
    # The walkthrough's task deletion left an audit event written by Taskboard in Axentra's trail.
    from axentra.data.database import DbScope

    events = board.ax.audit.list(DbScope.product(board.product_id), action="taskboard.task.delete")
    assert len(events.items) == 1
    assert events.items[0].tenant_id == result["users"]["alice"]["workspace"]
