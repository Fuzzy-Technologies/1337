from fuzzy1337.dev_commands import COMMANDS


def test_developer_commands_exist():
    assert {"test", "lint", "format", "check"}.issubset(COMMANDS)
