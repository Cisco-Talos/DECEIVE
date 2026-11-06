import pytest
from deceive.binding import render
from deceive.commands import virtual_path, file_view
from deceive.config import load_profile
from deceive.interaction import Session


def test_windows_drive_root_is_case_insensitive():
    p = load_profile('workbench-http-cmd')
    session = Session('edge', 'edge', 'guest', {})
    _, directories = file_view(p, session)
    assert virtual_path(p, session, 'c:\\') in directories


def test_runtime_template_expansion_is_bounded_before_building_output():
    with pytest.raises(ValueError, match='expansion'):
        render('${request.body}' * 90, {'request.body': 'x' * 100000}, runtime=True)


@pytest.mark.parametrize('files', [
    {r'C:\Temp\A': 'one', r'c:\temp\a': 'two'},
    {r'C:\Temp\..\A': 'one'},
])
def test_ambiguous_or_unnormalized_windows_baselines_fail_validation(files):
    from deceive.contracts import validate_profile
    p = load_profile('workbench-http-cmd')
    p.files = files
    with pytest.raises(ValueError, match='Virtual'):
        validate_profile(p)
