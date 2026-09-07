from fuzzy1337.cli import get_commands


def test_developer_commands_are_registered():
    commands = get_commands()

    assert set(commands) == {"test", "lint", "format", "check"}
