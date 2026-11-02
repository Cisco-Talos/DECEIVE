import pytest
from pydantic import ValidationError

from deceive.evaluate import Suite


@pytest.mark.parametrize("expect", [{}, {"headers": []}, {"state": {}}, {"json_value": None},
                                    {"contains": ""}, {"regex": ""}])
def test_acceptance_steps_cannot_pass_without_assertions(expect):
    with pytest.raises(ValidationError):
        Suite.model_validate({"id": "empty-assertion", "cases": [{"id": "empty", "steps": [
            {"path": "/", "expect": expect}]}]})


@pytest.mark.parametrize("expect", [{"body": ""}, {"status": 200}, {"exit_status": 0},
                                    {"body_base64": ""}, {"json_value": False}, {"json_value": 0},
                                    {"headers": [["x-proof", "yes"]]}, {"state": {"flag": "yes"}}])
def test_explicit_empty_values_are_real_assertions(expect):
    Suite.model_validate({"id": "explicit", "cases": [{"id": "exact", "steps": [
        {"path": "/", "expect": expect}]}]})
