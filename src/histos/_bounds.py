"""Small, dependency-free safety bounds shared across package layers."""

# Python's stdlib ``re`` engine has no execution budget or timeout and may hold the
# GIL while backtracking. Patterned values therefore need a hard ceiling in addition
# to the structural ReDoS screen. Ordinary, unpatterned text is governed by the
# aggregate gate input budget instead.
_MAX_PATTERN_INPUT = 4_096
