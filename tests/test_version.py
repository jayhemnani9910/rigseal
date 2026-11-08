from typer.testing import CliRunner

from rigseal import __version__
from rigseal.cli import app


def test_version_prints_version_and_exits_zero():
    result = CliRunner().invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == __version__
