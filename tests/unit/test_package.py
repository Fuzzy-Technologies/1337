def test_package_imports():
    import fuzzy1337

    assert fuzzy1337.__all__ == []
