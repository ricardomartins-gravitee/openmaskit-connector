from importlib.metadata import version

import pytest

from openmaskit_connector import __version__
from openmaskit_connector.cli import main


def test_package_and_source_cli_report_installed_project_version(capsys):
    expected = version("openmaskit-connector")
    assert __version__ == expected

    with pytest.raises(SystemExit) as result:
        main(["--version"])

    assert result.value.code == 0
    assert capsys.readouterr().out.strip() == expected
