def has_magic_word(content):
    return 1.0 if "magic" in str(content).lower() else 0.0


def mentions_magic_word(content):
    return has_magic_word(content)
