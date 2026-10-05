# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Text helpers for user-facing report strings."""


def plural(count, singular, plural_form=None):
    """Return ``"<count> <noun>"`` with the noun inflected for ``count``.

    The plural defaults to ``singular + "s"``; pass ``plural_form`` for
    irregular nouns (for example ``plural(n, "query", "queries")``).
    """
    if count == 1:
        return f"{count} {singular}"
    return f"{count} {plural_form or singular + 's'}"
