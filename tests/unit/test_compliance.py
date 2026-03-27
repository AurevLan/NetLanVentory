"""Tests for compliance framework evaluators."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.mark.asyncio
async def test_iso27001_returns_valid_structure():
    """ISO 27001 evaluator should return score and findings."""
    from netlanventory.core.compliance.iso27001 import evaluate_iso27001

    mock_session = AsyncMock()
    # Mock all DB queries to return empty results
    mock_result = MagicMock()
    mock_result.scalar_one.return_value = 0
    mock_result.scalars.return_value = MagicMock(all=MagicMock(return_value=[]))
    mock_result.all.return_value = []
    mock_session.execute.return_value = mock_result

    result = await evaluate_iso27001(mock_session)
    assert "score" in result
    assert "findings" in result
    assert isinstance(result["score"], int)
    assert isinstance(result["findings"], list)
    assert 0 <= result["score"] <= 100


@pytest.mark.asyncio
async def test_nis2_returns_valid_structure():
    """NIS2 evaluator should return score and findings."""
    from netlanventory.core.compliance.nis2 import evaluate_nis2

    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one.return_value = 0
    mock_result.scalars.return_value = MagicMock(all=MagicMock(return_value=[]))
    mock_result.all.return_value = []
    mock_session.execute.return_value = mock_result

    result = await evaluate_nis2(mock_session)
    assert "score" in result
    assert "findings" in result
    assert isinstance(result["score"], int)


@pytest.mark.asyncio
async def test_anssi_returns_valid_structure():
    """ANSSI evaluator should return score and findings."""
    from netlanventory.core.compliance.anssi import evaluate_anssi

    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one.return_value = 0
    mock_result.scalars.return_value = MagicMock(all=MagicMock(return_value=[]))
    mock_result.all.return_value = []
    mock_session.execute.return_value = mock_result

    result = await evaluate_anssi(mock_session)
    assert "score" in result
    assert "findings" in result
    assert isinstance(result["score"], int)
    assert 0 <= result["score"] <= 100


@pytest.mark.asyncio
async def test_iso27001_findings_have_required_fields():
    """Each finding should have control_id, title, status, severity."""
    from netlanventory.core.compliance.iso27001 import evaluate_iso27001

    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one.return_value = 10
    mock_result.scalars.return_value = MagicMock(all=MagicMock(return_value=[]))
    mock_result.all.return_value = []
    mock_session.execute.return_value = mock_result

    result = await evaluate_iso27001(mock_session)
    for finding in result["findings"]:
        assert "control_id" in finding
        assert "title" in finding
        assert "status" in finding
