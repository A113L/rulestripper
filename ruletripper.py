#!/usr/bin/env python3
"""
stripper.py — Hashcat Rule Extractor (Enhanced v1.1)
==============================================================================
Extracts hashcat rule chains empirically by decomposing target passwords
into their constituent token categories and building chains that reconstruct
each password from a base-wordlist stem.

NEW IN v1.1:
  • Insert-at-Position mode (iNX) — intra-word character insertions
  • Swap mode (*MN, k, K) — transposition detection
  • Range Extract/Omit mode (xNM, ONM) — contiguous character operations
  • Char-Duplicate mode (zN, ZN, q) — character-level duplication patterns
  • ASCII Transform mode (+N, -N, LN, RN, .N, ,N) — single-char offsets
  • Truncate mode ('N) — position-based truncation
  • Purge mode (@X) — character stripping
  • Multi-duplicate mode (pN) — word repetition
  • Separator Title-Case mode (eX) — custom separator title-casing

Extracted from rulest_v2 (GPU-Compatible Hashcat Rules Engine).
This standalone version adds multiprocessing (--workers) so all CPU cores
can be used without a GPU.

Five extraction modes (original)
────────────────────────────────
  LETTER MODE    boundary = digits + specials  →  stem = letters (+ leet)
  DIGIT MODE     boundary = letters + specials →  stem = pure digits
  REVERSE MODE   chain prefix 'r'
  DELETE-EDGE    chain prefix '[' or ']'
  DUPLICATE/FOLD chain 'd' or 'f'

NEW extraction modes (v1.1)
───────────────────────────
  INSERT MODE    chain 'iNX' — insert char X at position N
  SWAP MODE      chain '*MN', 'k', 'K' — transposition rules
  RANGE MODE     chain 'xNM', 'ONM' — contiguous extract/omit
  CHAR-DUP MODE  chain 'zN', 'ZN', 'q' — character-level duplication
  ASCII MODE     chain '+N', '-N', 'LN', 'RN', '.N', ',N' — ASCII transforms
  TRUNCATE MODE  chain "'N" — truncate at position N
  PURGE MODE     chain '@X' — remove all instances of char X
  REPEAT MODE    chain 'pN' — repeat word N times
  SEP-TITLE MODE chain 'eX' — title-case after separator X

Toggle-chain seeds (T-position patterns combined with leet ops) are generated
independently and appended to the output rule list.

Usage
─────
  python stripper.py BASE TARGET [options]

  positional:
    BASE                  Base wordlist (stems to match against)
    TARGET                Target wordlist (passwords to decompose)

  output:
    -o / --output FILE    Rule output file  (default: token_strip_rules.txt)

  extraction tuning:
    --max-depth N         Max rule chain length  (default: 0 = unlimited / 31)
    --min-stem N          Minimum stem length    (default: 4)
    --leet-amb N          Max ambiguous leet positions  (default: 3)
    --no-toggle-seeds     Skip toggle-chain seed generation
    --no-new-modes        Skip all v1.1 extraction modes
    --ascii-range N       Max ASCII offset for transform mode (default: 3)

  parallelism:
    --workers N           Worker processes (default: CPU count)
    --chunk-size N        Words per worker chunk (default: auto)

  misc:
    --debug               Verbose debug output
    --optimize            Enable chain optimization pass
"""

import os
import sys
import argparse
import string
import itertools
import multiprocessing as mp
from collections import defaultdict
from functools import partial
from typing import Dict, Set, Tuple, Optional, List, Iterator, Any
from tqdm import tqdm
import time
import datetime

# ====================================================================
# GLOBAL FLAGS  (set from CLI before workers are spawned)
# ====================================================================
VERBOSE       = False
ENABLE_NEW_MODES = True
ASCII_RANGE   = 3

MAX_WORD_LEN       = 256
MAX_HASHCAT_CHAIN  = 31
MAX_GPU_RULES      = 255

# ====================================================================
# COLORS
# ====================================================================
def _color_support() -> bool:
    """True only when stdout is a real TTY that understands ANSI escape codes."""
    import os
    if os.environ.get('NO_COLOR') or os.environ.get('TERM') == 'dumb':
        return False
    try:
        import colorama  # type: ignore
        colorama.init()
    except ImportError:
        pass
    return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()

_USE_COLOR = _color_support()

class C:
    RED     = '\033[91m' if _USE_COLOR else ''
    GREEN   = '\033[92m' if _USE_COLOR else ''
    YELLOW  = '\033[93m' if _USE_COLOR else ''
    BLUE    = '\033[94m' if _USE_COLOR else ''
    CYAN    = '\033[96m' if _USE_COLOR else ''
    MAGENTA = '\033[95m' if _USE_COLOR else ''
    BOLD    = '\033[1m'  if _USE_COLOR else ''
    DIM     = '\033[2m'  if _USE_COLOR else ''
    END     = '\033[0m'  if _USE_COLOR else ''

def red(t):    return f"{C.RED}{t}{C.END}"
def green(t):  return f"{C.GREEN}{t}{C.END}"
def yellow(t): return f"{C.YELLOW}{t}{C.END}"
def cyan(t):   return f"{C.CYAN}{t}{C.END}"
def bold(t):   return f"{C.BOLD}{t}{C.END}"
def dim(t):    return f"{C.DIM}{t}{C.END}"

# ====================================================================
# LOGGING
# ====================================================================
def log_info(msg: str)  -> None: print(msg)
def log_warn(msg: str)  -> None: print(yellow(f"[WARN] {msg}"))
def log_error(msg: str) -> None: print(red(f"[ERROR] {msg}"))
def log_debug(msg: str) -> None:
    if VERBOSE:
        print(f"{dim('[dbg]')} {msg}")

# ====================================================================
# TOKEN-STRIP CONSTANTS
# ====================================================================
TOKEN_STRIP_LEET_TABLE: List[Tuple[str, str, str]] = [
    ('@', 'a', 'sa@'),
    ('3', 'e', 'se3'),
    ('0', 'o', 'so0'),
    ('1', 'i', 'si1'),
    ('1', 'l', 'sl1'),
    ('5', 's', 'ss5'),
    ('$', 's', 'ss$'),
    ('7', 't', 'st7'),
    ('4', 'a', 'sa4'),
    ('!', 'i', 'si!'),
]

_TOKEN_STRIP_LEET_BY_CHAR: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
for _enc, _base, _rule in TOKEN_STRIP_LEET_TABLE:
    _TOKEN_STRIP_LEET_BY_CHAR[_enc].append((_base, _rule))

TOKEN_STRIP_LEET_CHARS: Set[str] = set(_TOKEN_STRIP_LEET_BY_CHAR.keys())

# LETTER mode: digits + specials are boundary, letters form the stem
TOKEN_STRIP_BOUNDARY: Set[str] = set('0123456789!@#$%^&*?.-_+()')

# DIGIT mode: letters + specials are boundary, pure digit run forms the stem
TOKEN_STRIP_ALPHA_BOUNDARY: Set[str] = (
    set(string.ascii_letters) | set('!@#$%^&*?.-_+()')
)

# ====================================================================
# RULE EXCLUSION FILTER
# ====================================================================
def should_exclude_rule(rule: str) -> bool:
    if not rule:
        return False
    if len(rule) == 1 and rule in ('_', 'M', '4', '6', 'Q'):
        return True
    if len(rule) == 2 and rule[0] in ('!', '/', '(', ')', '<', '>', '_'):
        return True
    if len(rule) == 3 and rule[0] in ('?', '=', 'v'):
        return True
    return False

# ====================================================================
# HASHCAT RULE VALIDATOR
# ====================================================================
class HashcatRuleValidator:
    MAX_GPU_RULES = MAX_GPU_RULES

    @staticmethod
    def is_digit(c: str) -> bool:
        return '0' <= c <= '9'

    @staticmethod
    def validate_rule_for_gpu(rule_str: str) -> bool:
        if should_exclude_rule(rule_str):
            return False
        pos = 0; cnt = 0; n = len(rule_str)
        isd = HashcatRuleValidator.is_digit
        while pos < n:
            c = rule_str[pos]
            if c == ' ':
                pos += 1; continue
            if c in ('p', 'z', 'Z'):
                cnt += 1; pos += 1
                if pos < n and isd(rule_str[pos]): pos += 1
                continue
            if c in (':', 'l', 'u', 'c', 'C', 't', 'r', 'd', 'f',
                     'a', 'q', 'k', 'K', 'E', '{', '}', '[', ']'):
                pos += 1; cnt += 1; continue
            if c in ('T', 'D', 'L', 'R', '+', '-', '.', ',', "'", 'y', 'Y'):
                pos += 1
                if pos >= n or not isd(rule_str[pos]): return False
                pos += 1; cnt += 1; continue
            if c in ('i', 'o', '3'):
                pos += 1
                if pos >= n or not isd(rule_str[pos]): return False
                pos += 1
                if pos >= n: return False
                pos += 1; cnt += 1; continue
            if c in ('x', '*', 'O'):
                pos += 1
                if pos >= n or not isd(rule_str[pos]): return False
                pos += 1
                if pos >= n or not isd(rule_str[pos]): return False
                pos += 1; cnt += 1; continue
            if c == 's':
                pos += 1
                if pos + 1 >= n: return False
                pos += 2; cnt += 1; continue
            if c in ('@', 'e', '$', '^'):
                pos += 1
                if pos >= n: return False
                pos += 1; cnt += 1; continue
            # Character class rules (hashcat 7.0+)
            if c == '~':
                pos += 1
                if pos >= n: return False
                if pos + 2 >= n: return False
                pos += 3; cnt += 1; continue
            return False
        return cnt <= HashcatRuleValidator.MAX_GPU_RULES

# ====================================================================
# PYTHON-SIDE RULE APPLICATOR
# ====================================================================
def _py_apply_single_rule(rule: str, word: str) -> Optional[str]:
    """Apply one hashcat rule token. Returns None for unsupported opcodes."""
    if not rule:
        return word
    w   = list(word.encode('utf-8'))
    cmd = rule[0]
    def dg(c): return ord(c) - 48 if '0' <= c <= '9' else -1
    try:
        if   cmd == ':': pass
        elif cmd == 'l': w = [c | 0x20 if 65<=c<=90 else c for c in w]
        elif cmd == 'u': w = [c & ~0x20 if 97<=c<=122 else c for c in w]
        elif cmd == 'c':
            if w:
                w[0] = w[0] & ~0x20 if 97<=w[0]<=122 else w[0]
                w[1:] = [c | 0x20 if 65<=c<=90 else c for c in w[1:]]
        elif cmd == 'C':
            if w:
                w[0] = w[0] | 0x20 if 65<=w[0]<=90 else w[0]
                w[1:] = [c & ~0x20 if 97<=c<=122 else c for c in w[1:]]
        elif cmd == 't':
            w = [c|0x20 if 65<=c<=90 else (c&~0x20 if 97<=c<=122 else c) for c in w]
        elif cmd == 'r': w = w[::-1]
        elif cmd == 'd': w = w + w
        elif cmd == 'f': w = w + w[::-1]
        elif cmd == '{':
            if len(w) > 1: w = w[1:] + [w[0]]
        elif cmd == '}':
            if len(w) > 1: w = [w[-1]] + w[:-1]
        elif cmd == '[':
            if w: w = w[1:]
        elif cmd == ']':
            if w: w = w[:-1]
        elif cmd == 'k':
            if len(w) >= 2: w[0], w[1] = w[1], w[0]
        elif cmd == 'K':
            if len(w) >= 2: w[-1], w[-2] = w[-2], w[-1]
        elif cmd == 'q':
            out = []
            for c in w: out += [c, c]
            w = out
        elif cmd == 'E':
            out = []; cap = True
            for c in w:
                out.append(c & ~0x20 if cap and 97<=c<=122 else c)
                cap = c in (32, 45, 95)
            w = out
        elif cmd == '^' and len(rule)==2: w = [ord(rule[1])] + w
        elif cmd == '$' and len(rule)==2: w = w + [ord(rule[1])]
        elif cmd == '@' and len(rule)==2:
            ch = ord(rule[1]); w = [c for c in w if c != ch]
        elif cmd == 'p' and len(rule)==2:
            n = dg(rule[1])
            if n > 0: orig = w[:]; [w.__iadd__(orig) for _ in range(n)]
        elif cmd == 'T' and len(rule)==2:
            p = dg(rule[1])
            if 0 <= p < len(w):
                c = w[p]; w[p] = c|0x20 if 65<=c<=90 else (c&~0x20 if 97<=c<=122 else c)
        elif cmd == 'D' and len(rule)==2:
            p = dg(rule[1])
            if 0 <= p < len(w): w.pop(p)
        elif cmd == 'L' and len(rule)==2:
            p = dg(rule[1])
            if 0 <= p < len(w): w[p] = (w[p] << 1) & 0xFF
        elif cmd == 'R' and len(rule)==2:
            p = dg(rule[1])
            if 0 <= p < len(w): w[p] = (w[p] >> 1) & 0xFF
        elif cmd == '+' and len(rule)==2:
            p = dg(rule[1])
            if 0 <= p < len(w): w[p] = (w[p] + 1) & 0xFF
        elif cmd == '-' and len(rule)==2:
            p = dg(rule[1])
            if 0 <= p < len(w): w[p] = (w[p] - 1) & 0xFF
        elif cmd in ('.', ',') and len(rule)==2:
            p = dg(rule[1]); delta = 1 if cmd == '.' else -1
            if 0 <= p < len(w): w[p] = (w[p] + delta) & 0xFF
        elif cmd == "'" and len(rule)==2:
            p = dg(rule[1])
            if 0 <= p < len(w): w = w[:p+1]
        elif cmd == 'z' and len(rule)==2:
            n = dg(rule[1])
            if n > 0 and w: w = [w[0]] * n + w
        elif cmd == 'Z' and len(rule)==2:
            n = dg(rule[1])
            if n > 0 and w: w = w + [w[-1]] * n
        elif cmd == 'y' and len(rule)==2:
            n = dg(rule[1])
            if n > 0: w = w[:n] + w
        elif cmd == 'Y' and len(rule)==2:
            n = dg(rule[1])
            if n > 0 and len(w) >= n: w = w + w[-n:]
        elif cmd == 's' and len(rule)==3:
            a, b = ord(rule[1]), ord(rule[2])
            w = [b if c==a else c for c in w]
        elif cmd == 'i' and len(rule)==3:
            p, ch = dg(rule[1]), ord(rule[2])
            if 0 <= p <= len(w): w.insert(p, ch)
        elif cmd == 'o' and len(rule)==3:
            p, ch = dg(rule[1]), ord(rule[2])
            if 0 <= p < len(w): w[p] = ch
        elif cmd == 'e' and len(rule)>=2:
            sep = ord(rule[1]); out = []; cap = True
            for c in w:
                out.append(c & ~0x20 if cap and 97<=c<=122 else c)
                cap = (c == sep)
            w = out
        elif cmd == 'x' and len(rule)==3:
            a, b = dg(rule[1]), dg(rule[2])
            if a > b: a, b = b, a
            w = w[a:b+1]
        elif cmd == 'O' and len(rule)==3:
            p, m = dg(rule[1]), dg(rule[2])
            if 0 <= p < len(w) and m > 0: w = w[:p] + w[p+m:]
        elif cmd == '*' and len(rule)==3:
            a, b = dg(rule[1]), dg(rule[2])
            if 0<=a<len(w) and 0<=b<len(w) and a!=b: w[a], w[b] = w[b], w[a]
        elif cmd == '3' and len(rule)==3:
            n, sep = dg(rule[1]), ord(rule[2]); cnt = 0
            for i, c in enumerate(w):
                if c == sep:
                    cnt += 1
                    if cnt == n and i+1 < len(w):
                        ci = w[i+1]
                        w[i+1] = ci|0x20 if 65<=ci<=90 else (ci&~0x20 if 97<=ci<=122 else ci)
                        break
        else:
            return None
    except Exception:
        return None
    try:
        return bytes(w).decode('utf-8')
    except Exception:
        return None


def py_apply_chain(chain: str, word: str) -> Optional[str]:
    """Apply a space-separated rule chain. Returns None if any op is unsupported."""
    cur = word
    for r in chain.split():
        cur = _py_apply_single_rule(r, cur)
        if cur is None:
            return None
    return cur

# ====================================================================
# CASE-INFERENCE HELPERS
# ====================================================================
def _hashcat_title_case(s: str) -> str:
    result   = list(s)
    cap_next = True
    for i, c in enumerate(result):
        if cap_next and 'a' <= c <= 'z':
            result[i] = c.upper()
            cap_next   = False
        if c in (' ', '-', '_'):
            cap_next = True
    return ''.join(result)


def _infer_case_rules(cased_stem: str) -> List[List[str]]:
    """
    Return all candidate lists of hashcat case ops that convert
    ``cased_stem.lower()`` into ``cased_stem``.
    """
    stem_lower = cased_stem.lower()

    if cased_stem == stem_lower:
        return [[]]

    candidates: List[List[str]] = []

    if cased_stem == stem_lower.upper():
        candidates.append(['u'])

    if (len(cased_stem) >= 1
            and cased_stem[0] == cased_stem[0].upper()
            and cased_stem[1:] == cased_stem[1:].lower()):
        candidates.append(['c'])

    if (len(cased_stem) >= 1
            and cased_stem[0] == cased_stem[0].lower()
            and cased_stem[1:] == cased_stem[1:].upper()):
        candidates.append(['C'])

    toggled = ''.join(c.lower() if c.isupper() else c.upper() for c in stem_lower)
    if cased_stem == toggled:
        candidates.append(['t'])

    if cased_stem == _hashcat_title_case(stem_lower):
        candidates.append(['E'])

    if not candidates:
        uppercase_positions = [i for i, c in enumerate(cased_stem)
                               if c != stem_lower[i]]
        if uppercase_positions and all(p <= 9 for p in uppercase_positions):
            candidates.append([f'T{p}' for p in uppercase_positions])

    return candidates

# ====================================================================
# LEET-DECODE HELPERS
# ====================================================================
def _leet_decode_variants(
    middle: str,
    max_ambiguous: int = 3,
) -> Iterator[Tuple[str, frozenset]]:
    for ch in middle:
        if not ch.isalpha() and ch not in TOKEN_STRIP_LEET_CHARS:
            return

    leet_positions: List[Tuple[int, str, List[Tuple[str, str]]]] = []
    for i, ch in enumerate(middle):
        if ch in TOKEN_STRIP_LEET_CHARS:
            options = _TOKEN_STRIP_LEET_BY_CHAR[ch]
            leet_positions.append((i, ch, options))

    if not leet_positions:
        yield (middle, frozenset())
        return

    n_ambiguous = sum(1 for _, _, opts in leet_positions if len(opts) > 1)
    if n_ambiguous > max_ambiguous:
        return

    choices_per_pos = [opts for _, _, opts in leet_positions]
    for combo in itertools.product(*choices_per_pos):
        decoded = list(middle)
        rules   = set()
        for (pos, _orig, _opts), (base_ch, rule_str) in zip(leet_positions, combo):
            decoded[pos] = base_ch
            rules.add(rule_str)
        decoded_str = ''.join(decoded)
        if all(ch.isalpha() for ch in decoded_str):
            yield (decoded_str, frozenset(rules))


def _decode_middle(
    middle: str,
    max_ambiguous: int = 3,
) -> Iterator[Tuple[str, frozenset, List[List[str]]]]:
    for leet_decoded, leet_rules in _leet_decode_variants(middle, max_ambiguous):
        cased_stem      = leet_decoded
        stem            = cased_stem.lower()
        case_candidates = _infer_case_rules(cased_stem)
        if not case_candidates:
            case_candidates = [[]]
        yield (stem, leet_rules, case_candidates)

# ====================================================================
# RULE-CHAIN ORDERING
# ====================================================================
def _rule_chain_orderings(
    case_ops:    List[str],
    leet_ops:    List[str],
    prepend_ops: List[str],
    append_ops:  List[str],
    leading_ops: Optional[List[str]] = None,
) -> List[List[str]]:
    lead = leading_ops or []
    seen: Set[tuple] = set()
    result: List[List[str]] = []

    def _add(ops: List[str]) -> None:
        full = lead + ops
        key  = tuple(full)
        if key not in seen:
            seen.add(key)
            result.append(full)

    _add(case_ops + leet_ops + prepend_ops + append_ops)
    if case_ops and leet_ops:
        _add(leet_ops + case_ops + prepend_ops + append_ops)
    if prepend_ops and (case_ops or leet_ops):
        _add(prepend_ops + case_ops + leet_ops + append_ops)

    return result

# ====================================================================
# BOUNDARY SCAN
# ====================================================================
def _boundary_scan(
    word:           str,
    boundary_chars: Set[str],
    max_prefix_len: int,
    max_suffix_len: int,
    min_stem_len:   int,
) -> List[Tuple[str, str, str]]:
    wlen    = len(word)
    triples: List[Tuple[str, str, str]] = []
    for p in range(0, min(max_prefix_len + 1, wlen + 1)):
        if p > 0 and word[p - 1] not in boundary_chars:
            break
        for s in range(0, min(max_suffix_len + 1, wlen - p + 1)):
            if s == 0:
                mid = word[p:]
                suf = ''
            else:
                mid = word[p: wlen - s]
                suf = word[wlen - s:]
            if s > 0 and word[wlen - s] not in boundary_chars:
                break
            if len(mid) >= min_stem_len:
                triples.append((word[:p], mid, suf))
    return triples

# ====================================================================
# CHAINS FROM MIDDLE SEGMENT
# ====================================================================
def _chains_from_middle(
    middle:      str,
    prefix:      str,
    suffix:      str,
    base_set:    Set[str],
    max_depth:   int,
    min_stem_len: int,
    max_leet_amb: int,
    leading_ops: Optional[List[str]] = None,
) -> Set[str]:
    target_word = prefix + middle + suffix
    lead        = leading_ops or []
    lead_depth  = len(lead)

    prepend_ops:   List[str] = []
    for c in reversed(prefix):
        prepend_ops.append('^' + c)
    append_ops:    List[str] = []
    for c in suffix:
        append_ops.append('$' + c)
    boundary_depth = len(prepend_ops) + len(append_ops)

    found: Set[str] = set()

    for stem, leet_rules, case_candidates in _decode_middle(middle, max_leet_amb):
        if len(stem) < min_stem_len or stem not in base_set:
            continue
        leet_ops: List[str] = sorted(leet_rules)
        for case_ops in case_candidates:
            total = lead_depth + len(case_ops) + len(leet_ops) + boundary_depth
            if total > max_depth:
                continue
            for ops in _rule_chain_orderings(
                case_ops, leet_ops, prepend_ops, append_ops,
                leading_ops=lead,
            ):
                if not ops or len(ops) > max_depth:
                    continue
                chain = ' '.join(ops)
                if not HashcatRuleValidator.validate_rule_for_gpu(chain):
                    continue
                if py_apply_chain(chain, stem) == target_word:
                    found.add(chain)
    return found

# ====================================================================
# NEW EXTRACTION MODES (v1.1)
# ====================================================================

def _extract_insert_mode(
    word: str, base_set: Set[str], max_depth: int,
    min_stem_len: int, max_leet_amb: int,
    base_by_len: Dict[int, Set[str]] = {},
) -> Set[str]:
    """
    INSERT MODE: Detect iNX rules for intra-word character insertions.

    Instead of iterating over base_set (O(N)), we generate stem candidates
    directly from the word by removing 1 or 2 characters and checking
    membership in base_set (O(1) per lookup).
    Total cost: O(wlen)  for single insertion,
                O(wlen²) for double insertion.
    """
    found: Set[str] = set()
    if max_depth < 2:
        return found

    wlen = len(word)

    # ── Single insertion ─────────────────────────────────────────────
    # stem = word with character at position p removed
    # rule: iPC  (insert char C at position P)
    if wlen - 1 >= min_stem_len:
        for pos in range(min(wlen, 10)):
            candidate = word[:pos] + word[pos + 1:]
            if candidate in base_set:
                rule = f"i{pos}{word[pos]}"
                if HashcatRuleValidator.validate_rule_for_gpu(rule):
                    if py_apply_chain(rule, candidate) == word:
                        found.add(rule)

    # ── Double insertion ─────────────────────────────────────────────
    # stem = word with chars at positions i and j (i < j) removed.
    # rules: [i{i}{word[i]}, i{j}{word[j]}]
    # After first rule, intermediate = word without char at j.
    # After second rule we get back to word. (positions remain valid since i < j.)
    if max_depth >= 3 and wlen - 2 >= min_stem_len:
        for i in range(min(wlen, 10)):
            for j in range(i + 1, min(wlen, 10)):
                candidate = word[:i] + word[i + 1:j] + word[j + 1:]
                if len(candidate) < min_stem_len:
                    continue
                if candidate in base_set:
                    chain = f"i{i}{word[i]} i{j}{word[j]}"
                    if HashcatRuleValidator.validate_rule_for_gpu(chain):
                        if py_apply_chain(chain, candidate) == word:
                            found.add(chain)

    return found


def _extract_swap_mode(
    word: str, base_set: Set[str], max_depth: int,
    min_stem_len: int, max_leet_amb: int,
) -> Set[str]:
    """
    SWAP MODE: Detect *MN, k, K transposition rules.
    Checks if the target is a transposition of any base word.
    """
    found: Set[str] = set()
    if max_depth < 1:
        return found

    wlen = len(word)
    if wlen < 2:
        return found

    # k: swap first two chars
    if wlen >= 2:
        k_swapped = word[1] + word[0] + word[2:]
        if len(k_swapped) >= min_stem_len and k_swapped in base_set:
            rule = 'k'
            if HashcatRuleValidator.validate_rule_for_gpu(rule):
                if py_apply_chain(rule, k_swapped) == word:
                    found.add(rule)

    # K: swap last two chars
    if wlen >= 2:
        K_swapped = word[:-2] + word[-1] + word[-2]
        if len(K_swapped) >= min_stem_len and K_swapped in base_set:
            rule = 'K'
            if HashcatRuleValidator.validate_rule_for_gpu(rule):
                if py_apply_chain(rule, K_swapped) == word:
                    found.add(rule)

    # *MN: swap positions M and N
    max_pos = min(wlen - 1, 9)
    for m in range(max_pos + 1):
        for n in range(m + 1, max_pos + 1):
            swapped = list(word)
            swapped[m], swapped[n] = swapped[n], swapped[m]
            swapped_str = ''.join(swapped)
            if len(swapped_str) >= min_stem_len and swapped_str in base_set:
                rule = f"*{m}{n}"
                if HashcatRuleValidator.validate_rule_for_gpu(rule):
                    if py_apply_chain(rule, swapped_str) == word:
                        found.add(rule)

    return found


def _extract_range_mode(
    word: str, base_set: Set[str], max_depth: int,
    min_stem_len: int, max_leet_amb: int,
    substr_idx: Dict[str, Set[str]] = {},
    omit_idx:   Dict[str, Set[str]] = {},
) -> Set[str]:
    """
    RANGE MODE: Detect xNM (extract range) and ONM (omit range) rules.

    Uses precomputed inverted indexes for O(1) lookup instead of O(base_set).
    substr_idx[substring] -> set of stems containing that substring at valid pos.
    omit_idx[result]      -> set of stems whose range-omit produces result.
    """
    found: Set[str] = set()
    if max_depth < 1:
        return found

    wlen = len(word)

    # xNM: extract range from stem → word
    # substr_idx[word] gives all stems that contain word as substring.
    # We still need to find which (N,M) positions apply.
    for stem in substr_idx.get(word, set()):
        if len(stem) < min_stem_len:
            continue
        slen = len(stem)
        for start in range(min(slen - wlen + 1, 10)):
            end = start + wlen - 1
            if end > 9:
                break
            if stem[start:end + 1] == word:
                rule = f"x{start}{end}"
                if HashcatRuleValidator.validate_rule_for_gpu(rule):
                    if py_apply_chain(rule, stem) == word:
                        found.add(rule)

    # ONM: omit range from stem → word
    # omit_idx[word] gives all stems that produce word when a range is omitted.
    for stem in omit_idx.get(word, set()):
        if len(stem) < min_stem_len or len(stem) <= wlen:
            continue
        slen   = len(stem)
        omit_n = slen - wlen
        for start in range(min(slen - omit_n + 1, 10)):
            if omit_n > 9 or start + omit_n > 10:
                continue
            if stem[:start] + stem[start + omit_n:] == word:
                rule = f"O{start}{omit_n}"
                if HashcatRuleValidator.validate_rule_for_gpu(rule):
                    if py_apply_chain(rule, stem) == word:
                        found.add(rule)

    return found


def _extract_char_duplicate_mode(
    word: str, base_set: Set[str], max_depth: int,
    min_stem_len: int,
) -> Set[str]:
    """
    CHAR-DUP MODE: Detect zN, ZN, q rules for character-level duplication.
    zN: duplicate first char N times (prepends N copies)
    ZN: duplicate last char N times (appends N copies)
    q: duplicate every char
    """
    found: Set[str] = set()
    if max_depth < 1:
        return found

    wlen = len(word)
    if wlen < 2:
        return found

    # q: duplicate every char
    # q on stem "abc" -> "aabbcc"
    # So word[::2] should equal stem, and word[i]==word[i+1] for all even i
    if wlen % 2 == 0:
        q_candidate = word[::2]
        if len(q_candidate) >= min_stem_len and q_candidate in base_set:
            valid = all(word[i] == word[i+1] for i in range(0, wlen, 2))
            if valid:
                rule = 'q'
                if HashcatRuleValidator.validate_rule_for_gpu(rule):
                    if py_apply_chain(rule, q_candidate) == word:
                        found.add(rule)

    # zN: duplicate first char N times
    # zN on stem "abc" with n=1 -> "aabc" (one extra 'a' at front)
    # zN prepends N copies: result = [stem[0]]*N + stem
    # So word = [first_char]*N + stem, meaning word[N:] == stem
    for n in range(1, min(10, wlen)):
        if wlen <= n:
            continue
        candidate = word[n:]
        if len(candidate) >= min_stem_len and candidate in base_set:
            first_char = word[0]
            # word[:n] should all be first_char, and candidate[0] should match
            if word[:n] == first_char * n and candidate[0] == first_char:
                rule = f"z{n}"
                if HashcatRuleValidator.validate_rule_for_gpu(rule):
                    if py_apply_chain(rule, candidate) == word:
                        found.add(rule)

    # ZN: duplicate last char N times
    # ZN on stem "abc" with n=1 -> "abcc" (one extra 'c' at end)
    # ZN appends N copies: result = stem + [stem[-1]]*N
    # So word = stem + [last_char]*N, meaning word[:-N] == stem
    for n in range(1, min(10, wlen)):
        if wlen <= n:
            continue
        candidate = word[:-n]
        if len(candidate) >= min_stem_len and candidate in base_set:
            last_char = word[-1]
            # word[-n:] should all be last_char, and candidate[-1] should match
            if word[-n:] == last_char * n and candidate[-1] == last_char:
                rule = f"Z{n}"
                if HashcatRuleValidator.validate_rule_for_gpu(rule):
                    if py_apply_chain(rule, candidate) == word:
                        found.add(rule)

    return found


def _extract_ascii_transform_mode(
    word: str, base_set: Set[str], max_depth: int,
    min_stem_len: int, max_leet_amb: int,
    base_by_len: Dict[int, Set[str]] = {},
    ascii_idx:   Dict[str, Any] = {},
) -> Set[str]:
    """
    ASCII TRANSFORM MODE: Detect +N, -N, LN, RN rules.

    All lookups are O(1) via ascii_idx (precomputed in extract_stripper_rules_mp).
    ascii_idx covers both single-position and full-word uniform-offset transforms.
    """
    found: Set[str] = set()
    if max_depth < 1:
        return found

    for stem, rule in ascii_idx.get(word, set()):
        if len(stem) < min_stem_len:
            continue
        if len(rule.split()) > max_depth:
            continue
        if HashcatRuleValidator.validate_rule_for_gpu(rule):
            if py_apply_chain(rule, stem) == word:
                found.add(rule)

    return found


def _extract_truncate_mode(
    word: str, base_set: Set[str], max_depth: int,
    min_stem_len: int, max_leet_amb: int,
    prefix_idx: Dict[str, Set[str]] = {},
) -> Set[str]:
    """
    TRUNCATE MODE: Detect 'N (truncate at position N) rules.

    stem[:wlen] == word  →  rule '(wlen-1)
    prefix_idx[word] gives all stems whose prefix equals word — O(1) lookup.
    """
    found: Set[str] = set()
    if max_depth < 1:
        return found

    wlen = len(word)
    if wlen < min_stem_len or wlen - 1 > 9:
        return found

    rule = f"'{wlen - 1}"
    if not HashcatRuleValidator.validate_rule_for_gpu(rule):
        return found

    for stem in prefix_idx.get(word, set()):
        if len(stem) < min_stem_len or len(stem) <= wlen:
            continue
        if py_apply_chain(rule, stem) == word:
            found.add(rule)

    return found


def _extract_purge_mode(
    word: str, base_set: Set[str], max_depth: int,
    min_stem_len: int, max_leet_amb: int,
    purge_idx: Dict[str, Set[str]] = {},
) -> Set[str]:
    """
    PURGE MODE: Detect @X (remove all instances of char X) rules.

    purge_idx[word] gives all stems s such that s.replace(c,'') == word
    for some character c — O(1) lookup instead of O(base_set) scan.
    """
    found: Set[str] = set()
    if max_depth < 1:
        return found

    wlen = len(word)
    word_chars = set(word)

    for stem in purge_idx.get(word, set()):
        if len(stem) < min_stem_len or len(stem) <= wlen:
            continue
        # The purged char is any char in stem that is NOT in word
        for char in set(stem) - word_chars:
            if stem.replace(char, '') == word:
                rule = f"@{char}"
                if HashcatRuleValidator.validate_rule_for_gpu(rule):
                    if py_apply_chain(rule, stem) == word:
                        found.add(rule)

    return found


def _extract_repeat_mode(
    word: str, base_set: Set[str], max_depth: int,
    min_stem_len: int,
) -> Set[str]:
    """
    REPEAT MODE: Detect pN (repeat word N times) rules.
    Alternative to d for word-level repetition.
    """
    found: Set[str] = set()
    if max_depth < 1:
        return found

    wlen = len(word)
    if wlen < 2 * min_stem_len:
        return found

    for n in range(2, min(10, wlen // min_stem_len + 1)):
        if wlen % n != 0:
            continue
        part_len = wlen // n
        if part_len < min_stem_len:
            continue

        parts = [word[i*part_len:(i+1)*part_len] for i in range(n)]
        if len(set(parts)) == 1:
            stem = parts[0]
            if stem in base_set:
                rule = f"p{n-1}"
                if HashcatRuleValidator.validate_rule_for_gpu(rule):
                    if py_apply_chain(rule, stem) == word:
                        found.add(rule)

    return found


def _extract_separator_title_mode(
    word: str, base_set: Set[str], max_depth: int,
    min_stem_len: int, max_leet_amb: int,
    base_lower_idx: Dict[str, Set[str]] = {},
) -> Set[str]:
    """
    SEPARATOR TITLE-CASE MODE: Detect eX (title-case after separator X) rules.
    For passwords like Password-123-Word from password-123-word.
    """
    found: Set[str] = set()
    if max_depth < 1:
        return found

    separators = ['-', '_', ' ', '.']

    for sep in separators:
        if sep not in word:
            continue

        lower_word = word.lower()

        # O(1) lowercase-exact lookup when index available; else linear scan.
        if base_lower_idx:
            stem_candidates = base_lower_idx.get(lower_word, set())
        else:
            stem_candidates = {s for s in base_set if s.lower() == lower_word}

        for stem in stem_candidates:
            slen = len(stem)
            if slen < min_stem_len:
                continue

            expected = []
            cap_next = True
            for c in stem:
                if cap_next and 'a' <= c <= 'z':
                    expected.append(c.upper())
                    cap_next = False
                else:
                    expected.append(c)
                if c == sep:
                    cap_next = True

            if ''.join(expected) == word:
                rule = f"e{sep}"
                if HashcatRuleValidator.validate_rule_for_gpu(rule):
                    if py_apply_chain(rule, stem) == word:
                        found.add(rule)

    return found

# ====================================================================
# ORIGINAL EXTRACTION MODES
# ====================================================================

def _extract_letter_mode(
    word: str, base_set: Set[str], max_depth: int,
    min_stem_len: int, max_leet_amb: int,
) -> Set[str]:
    found: Set[str] = set()
    for prefix, middle, suffix in _boundary_scan(
        word, TOKEN_STRIP_BOUNDARY, MAX_HASHCAT_CHAIN, MAX_HASHCAT_CHAIN, min_stem_len
    ):
        found |= _chains_from_middle(
            middle, prefix, suffix, base_set,
            max_depth, min_stem_len, max_leet_amb,
        )
    return found


def _extract_digit_mode(
    word: str, base_set: Set[str], max_depth: int,
    min_stem_len: int,
) -> Set[str]:
    found: Set[str] = set()
    for prefix, middle, suffix in _boundary_scan(
        word, TOKEN_STRIP_ALPHA_BOUNDARY, MAX_HASHCAT_CHAIN, MAX_HASHCAT_CHAIN, min_stem_len
    ):
        if not middle.isdigit():
            continue
        if middle not in base_set:
            continue
        prepend_ops: List[str] = []
        for c in reversed(prefix):
            prepend_ops.append('^' + c)
        append_ops: List[str] = []
        for c in suffix:
            append_ops.append('$' + c)
        total = len(prepend_ops) + len(append_ops)
        if total == 0 or total > max_depth:
            continue
        chain = ' '.join(prepend_ops + append_ops)
        if HashcatRuleValidator.validate_rule_for_gpu(chain):
            if py_apply_chain(chain, middle) == word:
                found.add(chain)
    return found


def _extract_reverse_mode(
    word: str, base_set: Set[str], max_depth: int,
    min_stem_len: int, max_leet_amb: int,
) -> Set[str]:
    found: Set[str] = set()
    if max_depth < 1:
        return found
    for prefix, middle, suffix in _boundary_scan(
        word, TOKEN_STRIP_BOUNDARY, MAX_HASHCAT_CHAIN, MAX_HASHCAT_CHAIN, min_stem_len
    ):
        found |= _chains_from_middle(
            middle[::-1], prefix, suffix, base_set,
            max_depth, min_stem_len, max_leet_amb,
            leading_ops=['r'],
        )
    return found


def _extract_duplicate_mode(
    word: str, base_set: Set[str], max_depth: int, min_stem_len: int,
) -> Set[str]:
    found: Set[str] = set()
    wlen = len(word)
    for op, builder in (
        ('d', lambda s: s + s),
        ('f', lambda s: s + s[::-1]),
    ):
        for half in range(min_stem_len, wlen // 2 + 1):
            stem_cand = word[:half]
            if builder(stem_cand) == word and stem_cand in base_set:
                chain = op
                if HashcatRuleValidator.validate_rule_for_gpu(chain):
                    if py_apply_chain(chain, stem_cand) == word:
                        found.add(chain)
    return found


def _extract_delete_edge_mode(
    word: str, base_set: Set[str], max_depth: int,
    min_stem_len: int, max_leet_amb: int,
) -> Set[str]:
    found: Set[str] = set()
    if max_depth < 1 or len(word) < min_stem_len + 1:
        return found
    for op, trimmed in (('[', word[1:]), (']', word[:-1])):
        for prefix, middle, suffix in _boundary_scan(
            trimmed, TOKEN_STRIP_BOUNDARY,
            MAX_HASHCAT_CHAIN, MAX_HASHCAT_CHAIN, min_stem_len
        ):
            found |= _chains_from_middle(
                middle, prefix, suffix, base_set,
                max_depth, min_stem_len, max_leet_amb,
                leading_ops=[op],
            )
    return found

# ====================================================================
# CHAIN OPTIMIZATION
# ====================================================================

def _optimize_chain(chain: str) -> Optional[str]:
    """
    Optimize a rule chain by removing redundant adjacent rules.
    Returns optimized chain or None if chain becomes empty/invalid.
    """
    if not chain:
        return chain

    rules = chain.split()
    if not rules:
        return chain

    optimized = []
    i = 0
    while i < len(rules):
        current = rules[i]

        if optimized and _rules_cancel(optimized[-1], current):
            optimized.pop()
            i += 1
            continue

        if optimized and _rules_mergeable(optimized[-1], current):
            merged = _merge_rules(optimized[-1], current)
            if merged:
                optimized[-1] = merged
                i += 1
                continue

        optimized.append(current)
        i += 1

    if not optimized:
        return None

    return ' '.join(optimized)


def _rules_cancel(rule1: str, rule2: str) -> bool:
    """Check if two adjacent rules cancel each other out."""
    if rule1 == 'r' and rule2 == 'r':
        return True
    if (rule1 == 'l' and rule2 == 'u') or (rule1 == 'u' and rule2 == 'l'):
        return True
    if rule1 == 't' and rule2 == 't':
        return True
    return False


def _rules_mergeable(rule1: str, rule2: str) -> bool:
    """Check if two adjacent rules can be merged."""
    if rule1.startswith('T') and rule2.startswith('T'):
        return rule1[1:] == rule2[1:]
    if rule1.startswith('s') and rule2.startswith('s'):
        return rule1[1] == rule2[1]
    return False


def _merge_rules(rule1: str, rule2: str) -> Optional[str]:
    """Merge two rules into one. Returns None if not mergeable."""
    if rule1.startswith('T') and rule2.startswith('T') and rule1[1:] == rule2[1:]:
        return rule2
    if rule1.startswith('s') and rule2.startswith('s') and rule1[1] == rule2[1]:
        return rule2
    return None

# ====================================================================
# TOGGLE-CHAIN SEED GENERATOR
# ====================================================================
def generate_toggle_chain_seeds(max_depth: int) -> List[str]:
    """
    Generate T-position toggle chains for injection as seed scaffolding.
    Patterns: sequential, even-position, odd-position, T0+leet.
    """
    LEET_OPS = ['sa@', 'se3', 'so0', 'si1', 'sl1', 'ss5', 'ss$', 'st7', 'sa4', 'si!']
    DOUBLE_LEET = [
        ('se3', 'si1'), ('se3', 'sl1'), ('sa@', 'so0'), ('ss5', 'so0'),
        ('si1', 'so0'), ('se3', 'so0'), ('ss$', 'se3'), ('sa4', 'sl1'),
    ]
    seeds: Set[str] = set()

    def _add(ops: List[str]) -> None:
        if not ops or len(ops) > max_depth:
            return
        chain = ' '.join(ops)
        if HashcatRuleValidator.validate_rule_for_gpu(chain):
            seeds.add(chain)

    # 1. Sequential T0 T1 ... TN
    for n in range(0, min(10, max_depth)):
        t_ops = [f'T{i}' for i in range(n + 1)]
        _add(t_ops)
        for leet in LEET_OPS:
            _add(t_ops + [leet])
            if n >= 1:
                _add([leet] + t_ops)
        for l1, l2 in DOUBLE_LEET:
            _add(t_ops + [l1, l2])
            _add([l1] + t_ops + [l2])

    # 2. Even-position T0 T2 T4 T6 T8
    for n in range(1, min(5, max_depth)):
        t_ops = [f'T{i * 2}' for i in range(n + 1)]
        _add(t_ops)
        for leet in LEET_OPS:
            _add(t_ops + [leet])
            _add([leet] + t_ops)
        for l1, l2 in DOUBLE_LEET:
            _add(t_ops + [l1, l2])

    # 3. Odd-position T1 T3 T5 T7 T9
    for n in range(1, min(5, max_depth)):
        t_ops = [f'T{i * 2 + 1}' for i in range(n + 1)]
        _add(t_ops)
        for leet in LEET_OPS:
            _add(t_ops + [leet])
            _add([leet] + t_ops)
        for l1, l2 in DOUBLE_LEET:
            _add(t_ops + [l1, l2])

    # 4. T0 + single leet (depth 2, highest utility)
    for leet in LEET_OPS:
        _add(['T0', leet])
        _add([leet, 'T0'])

    return sorted(seeds)

# ====================================================================
# MULTIPROCESSING — WORKER
# ====================================================================
_worker_base_set:       Set[str]              = set()
_worker_base_by_len:    Dict[int, Set[str]]   = {}
_worker_base_lower_idx: Dict[str, Set[str]]   = {}
# Precomputed inverted indexes — built once, inherited by workers via CoW fork
_worker_purge_idx:       Dict[str, Set[str]]  = {}  # purge(stem,c)  -> stems
_worker_substr_idx:      Dict[str, Set[str]]  = {}  # substr(stem)   -> stems (xNM)
_worker_omit_idx:        Dict[str, Set[str]]  = {}  # omit_range(s)  -> stems (ONM)
_worker_prefix_idx:      Dict[str, Set[str]]  = {}  # prefix(stem,l) -> stems (truncate)
_worker_ascii_idx:       Dict[str, Set[Tuple[str,str]]] = {}  # transformed -> {(stem,rule)}

def _worker_init(
    base_set=None, base_by_len=None, base_lower_idx=None,
    purge_idx=None, substr_idx=None, omit_idx=None,
    prefix_idx=None, ascii_idx=None,
) -> None:
    """Pool initialiser.
    With fork globals are inherited via CoW — args are None.
    With spawn they must be passed explicitly.
    """
    global _worker_base_set, _worker_base_by_len, _worker_base_lower_idx
    global _worker_purge_idx, _worker_substr_idx, _worker_omit_idx
    global _worker_prefix_idx, _worker_ascii_idx
    if base_set       is not None: _worker_base_set       = base_set
    if base_by_len    is not None: _worker_base_by_len    = base_by_len
    if base_lower_idx is not None: _worker_base_lower_idx = base_lower_idx
    if purge_idx      is not None: _worker_purge_idx      = purge_idx
    if substr_idx     is not None: _worker_substr_idx     = substr_idx
    if omit_idx       is not None: _worker_omit_idx       = omit_idx
    if prefix_idx     is not None: _worker_prefix_idx     = prefix_idx
    if ascii_idx      is not None: _worker_ascii_idx      = ascii_idx


def _process_chunk(args: Tuple) -> Set[str]:
    """
    Worker function — process a chunk of target words.
    Returns the set of discovered rule chains.
    """
    (words_chunk, max_depth, min_stem_len, max_leet_amb, enable_new_modes, ascii_range) = args

    base_set       = _worker_base_set
    base_by_len    = _worker_base_by_len
    base_lower_idx = _worker_base_lower_idx
    purge_idx      = _worker_purge_idx
    substr_idx     = _worker_substr_idx
    omit_idx       = _worker_omit_idx
    prefix_idx     = _worker_prefix_idx
    ascii_idx      = _worker_ascii_idx
    found:  Set[str] = set()

    for word in words_chunk:
        if not word or len(word) > MAX_WORD_LEN:
            continue

        n_digits  = sum(1 for c in word if c.isdigit())
        n_alpha   = sum(1 for c in word if c.isalpha())

        digit_primary = n_digits > n_alpha

        if digit_primary:
            found |= _extract_digit_mode(
                word, base_set, max_depth, min_stem_len,
            )
            if n_alpha >= min_stem_len:
                found |= _extract_letter_mode(
                    word, base_set, max_depth, min_stem_len, max_leet_amb,
                )
        else:
            found |= _extract_letter_mode(
                word, base_set, max_depth, min_stem_len, max_leet_amb,
            )
            if n_digits > 0:
                found |= _extract_digit_mode(
                    word, base_set, max_depth, min_stem_len,
                )

        if max_depth >= 2:
            found |= _extract_reverse_mode(
                word, base_set, max_depth, min_stem_len, max_leet_amb,
            )
            found |= _extract_delete_edge_mode(
                word, base_set, max_depth, min_stem_len, max_leet_amb,
            )

        if len(word) >= 2 * min_stem_len:
            found |= _extract_duplicate_mode(
                word, base_set, max_depth, min_stem_len,
            )

        # NEW MODES (v1.1)
        if enable_new_modes:
            if max_depth >= 2:
                found |= _extract_insert_mode(
                    word, base_set, max_depth, min_stem_len, max_leet_amb,
                    base_by_len,
                )

            if max_depth >= 1:
                found |= _extract_swap_mode(
                    word, base_set, max_depth, min_stem_len, max_leet_amb,
                )

            if max_depth >= 1:
                found |= _extract_range_mode(
                    word, base_set, max_depth, min_stem_len, max_leet_amb,
                    substr_idx, omit_idx,
                )

            if max_depth >= 1:
                found |= _extract_char_duplicate_mode(
                    word, base_set, max_depth, min_stem_len,
                )

            if max_depth >= 1:
                found |= _extract_ascii_transform_mode(
                    word, base_set, max_depth, min_stem_len, max_leet_amb,
                    base_by_len, ascii_idx,
                )

            if max_depth >= 1:
                found |= _extract_truncate_mode(
                    word, base_set, max_depth, min_stem_len, max_leet_amb,
                    prefix_idx,
                )

            if max_depth >= 1:
                found |= _extract_purge_mode(
                    word, base_set, max_depth, min_stem_len, max_leet_amb,
                    purge_idx,
                )

            if max_depth >= 1 and len(word) >= 2 * min_stem_len:
                found |= _extract_repeat_mode(
                    word, base_set, max_depth, min_stem_len,
                )

            if max_depth >= 1:
                found |= _extract_separator_title_mode(
                    word, base_set, max_depth, min_stem_len, max_leet_amb,
                    base_lower_idx,
                )

    return found

# ====================================================================
# MULTIPROCESSING DRIVER
# ====================================================================
def extract_stripper_rules_mp(
    target_words:       List[str],
    base_set:           Set[str],
    max_depth:          int  = 0,
    min_stem_len:       int  = 4,
    max_leet_ambiguity: int  = 3,
    workers:            int  = 0,
    chunk_size:         int  = 0,
    enable_new_modes:   bool = True,
    ascii_range:        int  = 3,
) -> List[str]:
    """
     Stripper extraction with multiprocessing.
    """
    if max_depth <= 0:
        max_depth = MAX_HASHCAT_CHAIN

    n_workers  = workers  or mp.cpu_count()
    n_words    = len(target_words)

    if chunk_size <= 0:
        chunk_size = max(500, n_words // (n_workers * 4) + 1)

    chunks = [
        target_words[i: i + chunk_size]
        for i in range(0, n_words, chunk_size)
    ]
    n_chunks = len(chunks)

    task_args = [
        (chunk, max_depth, min_stem_len, max_leet_ambiguity, enable_new_modes, ascii_range)
        for chunk in chunks
    ]

    sep_line = cyan("─" * 56)
    log_info("")
    log_info(sep_line)
    log_info("  " + bold(green("stripper")) + " — Hashcat Rule Extractor")
    log_info("  " + bold(cyan("v1.1")) + " — 14 extraction modes")
    log_info(sep_line)
    log_info("  target words  : " + bold(str(n_words)))
    log_info("  base stems    : " + bold(str(len(base_set))))
    log_info("  workers       : " + bold(str(n_workers)))
    log_info("  chunk size    : " + bold(str(chunk_size)) + "  (" + str(n_chunks) + " tasks)")
    log_info("  max depth     : " + bold(str(max_depth)))
    log_info("  min stem      : " + bold(str(min_stem_len)))
    log_info("  leet-amb      : " + bold(str(max_leet_ambiguity)))
    log_info("  new modes     : " + bold(green("enabled") if enable_new_modes else yellow("disabled")))
    log_info("  ascii range   : " + bold(str(ascii_range)))
    print()

    found: Set[str] = set()
    t0 = time.time()

    # Build lookup indexes ONCE — workers inherit via fork (CoW, zero copy)
    log_info("  Building lookup indexes …")
    sys.stdout.flush()
    base_by_len: Dict[int, Set[str]] = defaultdict(set)
    base_lower_idx: Dict[str, Set[str]] = defaultdict(set)
    # Inverted indexes for O(1) lookups in slow extraction modes
    purge_idx:  Dict[str, Set[str]] = defaultdict(set)
    substr_idx: Dict[str, Set[str]] = defaultdict(set)
    omit_idx:   Dict[str, Set[str]] = defaultdict(set)
    prefix_idx: Dict[str, Set[str]] = defaultdict(set)
    ascii_idx:  Dict[str, set]      = defaultdict(set)

    for w in base_set:
        wlen = len(w)
        base_by_len[wlen].add(w)
        base_lower_idx[w.lower()].add(w)

        # purge_idx: stem.replace(c,'') -> stem
        for c in set(w):
            purge_idx[w.replace(c, '')].add(w)

        # substr_idx: all substrings at valid xNM positions -> stem
        for start in range(min(wlen, 10)):
            for end in range(start + 1, min(wlen + 1, 11)):
                substr_idx[w[start:end]].add(w)

        # omit_idx: stem with contiguous range removed -> stem
        for start in range(min(wlen, 10)):
            for omit_n in range(1, min(10, wlen - start) + 1):
                if start + omit_n > 10:
                    break
                result = w[:start] + w[start + omit_n:]
                if result:
                    omit_idx[result].add(w)

        # prefix_idx: stem[:l] -> stem  (for truncate 'N, l = N+1 = 1..9)
        for end in range(1, min(wlen, 10)):
            prefix_idx[w[:end]].add(w)

        # ascii_idx: single-position transforms -> (stem, rule)
        for pos in range(min(wlen, 10)):
            sc = ord(w[pos])
            for delta, rchar in ((1, '+'), (-1, '-')):
                t = w[:pos] + chr((sc + delta) & 0xFF) + w[pos + 1:]
                ascii_idx[t].add((w, f"{rchar}{pos}"))
            for shifted, rchar in (
                (chr((sc << 1) & 0xFF), 'L'),
                (chr((sc >> 1) & 0xFF), 'R'),
            ):
                t = w[:pos] + shifted + w[pos + 1:]
                ascii_idx[t].add((w, f"{rchar}{pos}"))
        # ascii_idx: multi-position uniform-offset (full +1 / -1 shift)
        # Covers "+0 +1 +2 ... +N" type rules without O(N) per-word scan.
        for delta, rchar in ((1, '+'), (-1, '-')):
            full_t = ''.join(chr((ord(c) + delta) & 0xFF) for c in w)
            if full_t != w:
                chain = ' '.join(f"{rchar}{p}" for p in range(min(wlen, 10)))
                ascii_idx[full_t].add((w, chain))

    base_by_len    = dict(base_by_len)
    base_lower_idx = dict(base_lower_idx)
    purge_idx      = dict(purge_idx)
    substr_idx     = dict(substr_idx)
    omit_idx       = dict(omit_idx)
    prefix_idx     = dict(prefix_idx)
    ascii_idx      = dict(ascii_idx)

    use_fork = hasattr(os, 'fork')
    ctx = mp.get_context('fork' if use_fork else 'spawn')

    # Set globals BEFORE Pool() — forked workers inherit via CoW,
    # no pickling of large dicts through pipes.
    global _worker_base_set, _worker_base_by_len, _worker_base_lower_idx
    global _worker_purge_idx, _worker_substr_idx, _worker_omit_idx
    global _worker_prefix_idx, _worker_ascii_idx
    _worker_base_set       = base_set
    _worker_base_by_len    = base_by_len
    _worker_base_lower_idx = base_lower_idx
    _worker_purge_idx      = purge_idx
    _worker_substr_idx     = substr_idx
    _worker_omit_idx       = omit_idx
    _worker_prefix_idx     = prefix_idx
    _worker_ascii_idx      = ascii_idx

    if use_fork:
        pool_kwargs: dict = dict(processes=n_workers,
                                 initializer=_worker_init)
    else:
        pool_kwargs = dict(processes=n_workers,
                           initializer=_worker_init,
                           initargs=(base_set, base_by_len, base_lower_idx,
                                     purge_idx, substr_idx, omit_idx,
                                     prefix_idx, ascii_idx))

    with ctx.Pool(**pool_kwargs) as pool:
        with tqdm(
            total=n_words,
            desc=green("  Extracting"),
            unit="word",
            ncols=88,
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}] {postfix}",
        ) as pbar:
            for (task_arg, chunk_result) in zip(
                task_args,
                pool.imap_unordered(_process_chunk, task_args),
            ):
                found |= chunk_result
                pbar.set_postfix({"rules": cyan(str(len(found)))}, refresh=False)
                pbar.update(len(task_arg[0]))

    elapsed = time.time() - t0
    log_info("")
    log_info("[P0]  " + green("Done") + "  —  " + f"{elapsed:.1f}s")
    return sorted(found)

# ====================================================================
# STATS PRINTER
# ====================================================================
def _log_stripper_stats(n_words: int, rules: List[str]) -> None:
    if not rules:
        log_info("[P0]  " + yellow("0") + " rules extracted  (" + f"{n_words:,}" + " words scanned)")
        return

    depth_dist:  Dict[int, int] = defaultdict(int)
    mode_counts: Dict[str, int] = defaultdict(int)

    for r in rules:
        depth_dist[len(r.split())] += 1
        first = r.split()[0] if r.split() else ''
        if first == 'r':            mode_counts['reverse']  += 1
        elif first == 'd':          mode_counts['dup']       += 1
        elif first == 'f':          mode_counts['fold']      += 1
        elif first in ('[', ']'):   mode_counts['del-edge']  += 1
        elif first.startswith('T') and len(first) == 2:
                                    mode_counts['toggle']    += 1
        elif first.startswith('i') and len(first) == 3:
                                    mode_counts['insert']    += 1
        elif first.startswith('*') and len(first) == 3:
                                    mode_counts['swap']      += 1
        elif first.startswith('x') and len(first) == 3:
                                    mode_counts['range-ext'] += 1
        elif first.startswith('O') and len(first) == 3:
                                    mode_counts['range-omit']+= 1
        elif first.startswith('z') and len(first) == 2:
                                    mode_counts['char-dup-f']+= 1
        elif first.startswith('Z') and len(first) == 2:
                                    mode_counts['char-dup-l']+= 1
        elif first == 'q':          mode_counts['char-dup-all']+= 1
        elif first.startswith('+') and len(first) == 2:
                                    mode_counts['ascii-inc'] += 1
        elif first.startswith('-') and len(first) == 2:
                                    mode_counts['ascii-dec'] += 1
        elif first.startswith("'") and len(first) == 2:
                                    mode_counts['truncate']  += 1
        elif first.startswith('@') and len(first) == 2:
                                    mode_counts['purge']     += 1
        elif first.startswith('p') and len(first) == 2:
                                    mode_counts['repeat']    += 1
        elif first.startswith('e') and len(first) == 2:
                                    mode_counts['sep-title'] += 1
        elif first.startswith('k') and len(first) == 1:
                                    mode_counts['swap-adj']  += 1
        elif first.startswith('K') and len(first) == 1:
                                    mode_counts['swap-adj-l']+= 1
        elif all(c.isdigit() or c in ('^', '$', ' ')
                 for c in r) and any(c.isdigit() for c in r):
                                    mode_counts['digit-bnd'] += 1
        else:                       mode_counts['letter']    += 1

    depth_summary = '  '.join(f"d{d}:{depth_dist[d]:,}" for d in sorted(depth_dist))
    mode_str      = '  '.join(f"{k}:{v}" for k, v in sorted(mode_counts.items()) if v)

    log_info(
        "[P0]  " + bold(green(str(len(rules)))) + " rules extracted  "
        "(" + f"{n_words:,}" + " words)  [" + depth_summary + "]"
    )
    if mode_str:
        log_info("[P0]  Modes : " + dim(mode_str))

# ====================================================================
# WORDLIST LOADER
# ====================================================================
def load_wordlist(path: str) -> List[str]:
    log_info("[LOAD]  " + path + " …")
    words: List[str] = []
    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
        for line in fh:
            w = line.rstrip('\n\r')
            if w:
                words.append(w)
    log_info("        " + bold(str(len(words))) + " words loaded")
    return words

# ====================================================================
# CLI
# ====================================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='stripper',
        description='Stripper — Hashcat Rule Extractor (Enhanced v1.1)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument('base_wordlist',   help='Base wordlist (stems)')
    p.add_argument('target_wordlist', help='Target wordlist (passwords to decompose)')

    out = p.add_argument_group('output')
    out.add_argument('-o', '--output', default='stripper_rules.txt',
                     help='Output rule file  (default: stripper_rules.txt)')

    tun = p.add_argument_group('extraction tuning')
    tun.add_argument('--max-depth',    type=int, default=0,
                     metavar='N', help='Max rule chain length (0 = 31)')
    tun.add_argument('--min-stem',     type=int, default=4,
                     metavar='N', help='Minimum stem length  (default: 4)')
    tun.add_argument('--leet-amb',     type=int, default=3,
                     metavar='N', help='Max ambiguous leet positions  (default: 3)')
    tun.add_argument('--no-toggle-seeds', action='store_true',
                     help='Skip toggle-chain seed generation')
    tun.add_argument('--no-new-modes', action='store_true',
                     help='Skip all v1.1 extraction modes (insert, swap, range, etc.)')
    tun.add_argument('--ascii-range',  type=int, default=3,
                     metavar='N', help='Max ASCII offset for transform mode (default: 3)')

    par = p.add_argument_group('parallelism')
    par.add_argument('--workers',    type=int, default=0,
                     metavar='N', help='Worker processes (default: CPU count)')
    par.add_argument('--chunk-size', type=int, default=0,
                     metavar='N', help='Words per worker chunk (default: auto)')

    misc = p.add_argument_group('misc')
    misc.add_argument('--debug', action='store_true',
                      help='Verbose debug output')
    return p


def main() -> None:
    global VERBOSE, ENABLE_NEW_MODES, ASCII_RANGE

    parser = build_parser()
    args   = parser.parse_args()

    VERBOSE = args.debug
    ENABLE_NEW_MODES = not args.no_new_modes
    ASCII_RANGE = args.ascii_range

    sep = cyan("─" * 56)
    BANNER = (
        "  ______ _   _ _      _____ _____ ___________ _________________ ___________\n"
        "  | ___ \\ | | | |    |  ___/  ___|_   _| ___ \\_   _| ___ \\ ___ \\  ___| ___ \\\n"
        "  | |_/ / | | | |    | |__ \\ `--.  | | | |_/ / | | | |_/ / |_/ / |__ | |_/ /\n"
        "  |    /| | | | |    |  __| `--. \\ | | |    /  | | |  __/|  __/|  __||    /\n"
        "  | |\\ \\| |_| | |____| |___/\\__/ / | | | |\\ \\ _| |_| |   | |   | |___| |\\ \\\n"
        "  \\_| \\_|\\___/\\_____/\\____/\\____/  \\_/ \\_| \\_|\\___/\\_|   \\_|   \\____/\\_| \\_|"
    )
    print(cyan(BANNER))
    print("  " + bold("Hashcat Rule Extractor") + "  " + green("v1.1") +
          "  —  " + cyan("14 extraction modes") + "  |  multiprocessing")
    print()

    # Load wordlists
    base_words   = load_wordlist(args.base_wordlist)
    target_words = load_wordlist(args.target_wordlist)
    base_set: Set[str] = set(w.lower() for w in base_words)
    print("")

    t_start = time.time()

    # Token-strip extraction (multiprocessing)
    rules = extract_stripper_rules_mp(
        target_words,
        base_set,
        max_depth          = args.max_depth,
        min_stem_len       = args.min_stem,
        max_leet_ambiguity = args.leet_amb,
        workers            = args.workers,
        chunk_size         = args.chunk_size,
        enable_new_modes   = ENABLE_NEW_MODES,
        ascii_range        = args.ascii_range,
    )

    # Toggle-chain seeds
    toggle_seeds: List[str] = []
    if not args.no_toggle_seeds:
        max_d = args.max_depth if args.max_depth > 0 else MAX_HASHCAT_CHAIN
        toggle_seeds = generate_toggle_chain_seeds(max_d)
        log_info("[P0]  Toggle seeds: " + bold(green(str(len(toggle_seeds)))))
        all_rules = sorted(set(rules) | set(toggle_seeds))
    else:
        all_rules = rules

    # Stats
    print("")
    _log_stripper_stats(len(target_words), all_rules)

    # Write output
    depth_dist: Dict[int, int] = defaultdict(int)
    for r in all_rules:
        if r != ':':
            depth_dist[len(r.split())] += 1
    depth_summary = '  '.join(f"d{d}:{depth_dist[d]:,}" for d in sorted(depth_dist))

    with open(args.output, 'w', encoding='utf-8') as fh:
        fh.write("# stripper — Hashcat Rule Extractor (Enhanced v1.1)\n")
        fh.write("# Generated      : " + datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "\n")
        fh.write("# Base           : " + os.path.basename(args.base_wordlist) + "\n")
        fh.write("# Target         : " + os.path.basename(args.target_wordlist) + "\n")
        fh.write("# Depth          : 1–" + str(args.max_depth or MAX_HASHCAT_CHAIN) + "\n")
        fh.write("# Workers        : " + str(args.workers or mp.cpu_count()) + "\n")
        fh.write("# New modes      : " + ('enabled' if ENABLE_NEW_MODES else 'disabled') + "\n")
        fh.write("# Toggle seeds   : " + ('included' if not args.no_toggle_seeds else 'skipped') + "\n")
        fh.write("#\n")
        fh.write("# Rules          : " + f"{len(all_rules):,}" + "  (" + depth_summary + ")\n")
        fh.write("#   stem-derived : " + f"{len(rules):,}" + "\n")
        fh.write("#   toggle-seeds : " + f"{len(toggle_seeds):,}" + "\n")
        fh.write("#\n")
        fh.write(":\n")
        for rule in all_rules:
            if rule != ':':
                fh.write(rule + "\n")

    elapsed = time.time() - t_start
    print("")
    log_info(sep)
    elapsed_str = f"{elapsed:.1f}s"
    log_info("  " + bold("DONE") + "  finished in " + bold(elapsed_str) + f" ({elapsed/60:.1f} min)")
    log_info(sep)
    log_info("  Rules written    : " + bold(green(str(len(all_rules)))))
    log_info("    stem-derived   : " + bold(str(len(rules))))
    log_info("    toggle-seeds   : " + bold(str(len(toggle_seeds))))
    log_info("  Output file      : " + bold(args.output))
    log_info(sep)
    print("")




# ====================================================================
# SELF-TEST (for verification)
# ====================================================================
def _self_test():
    """Run quick self-test to verify all extraction modes work."""
    base_set = {'password', 'admin', 'test', 'hello', 'world', 'abc123', 'letmein', 'pass-word'}

    # Build mini-indexes so rewritten functions work in isolation
    from collections import defaultdict as _dd
    _bbl:    Dict[int,Set[str]]         = _dd(set)
    _sub:    Dict[str,Set[str]]         = _dd(set)
    _omit:   Dict[str,Set[str]]         = _dd(set)
    _pfx:    Dict[str,Set[str]]         = _dd(set)
    _asc:    Dict[str,set]              = _dd(set)
    _purge:  Dict[str,Set[str]]         = _dd(set)
    for _w in base_set:
        _n = len(_w)
        _bbl[_n].add(_w)
        for c in set(_w):
            _purge[_w.replace(c,'')].add(_w)
        for _s in range(min(_n,10)):
            for _e in range(_s+1, min(_n+1,11)):
                _sub[_w[_s:_e]].add(_w)
            for _on in range(1, min(10,_n-_s)+1):
                if _s+_on<=10:
                    _r = _w[:_s]+_w[_s+_on:]
                    if _r: _omit[_r].add(_w)
            if _s < _n-1:
                _pfx[_w[:_s+1]].add(_w)
        for _p in range(min(_n,10)):
            _sc = ord(_w[_p])
            for _d,_rc in ((1,'+'),((-1)&0xFF,'-')):
                _t = _w[:_p]+chr((_sc+_d)&0xFF)+_w[_p+1:]
                _asc[_t].add((_w,f"{_rc}{_p}"))
            for _sh,_rc in ((chr((_sc<<1)&0xFF),'L'),(chr((_sc>>1)&0xFF),'R')):
                _asc[_w[:_p]+_sh+_w[_p+1:]].add((_w,f"{_rc}{_p}"))
    _bbl=dict(_bbl); _sub=dict(_sub); _omit=dict(_omit)
    _pfx=dict(_pfx); _asc=dict(_asc); _purge=dict(_purge)

    # Also build indexes for single-stem test cases
    def _mk(bs):
        bb=_dd(set); su=_dd(set); om=_dd(set); pf=_dd(set); ac=_dd(set); pu=_dd(set)
        for w in bs:
            n=len(w); bb[n].add(w)
            for c in set(w): pu[w.replace(c,'')].add(w)
            for s in range(min(n,10)):
                for e in range(s+1,min(n+1,11)): su[w[s:e]].add(w)
                for on in range(1,min(10,n-s)+1):
                    if s+on<=10:
                        r=w[:s]+w[s+on:]
                        if r: om[r].add(w)
                if s<n-1: pf[w[:s+1]].add(w)
            for p in range(min(n,10)):
                sc=ord(w[p])
                for d,rc in ((1,'+'),((-1)&0xFF,'-')):
                    t=w[:p]+chr((sc+d)&0xFF)+w[p+1:]; ac[t].add((w,f"{rc}{p}"))
                for sh,rc in ((chr((sc<<1)&0xFF),'L'),(chr((sc>>1)&0xFF),'R')):
                    ac[w[:p]+sh+w[p+1:]].add((w,f"{rc}{p}"))
            for d,rc in ((1,'+'),((-1)&0xFF,'-')):
                ft=''.join(chr((ord(c)+d)&0xFF) for c in w)
                if ft!=w: ac[ft].add((w,' '.join(f'{rc}{p}' for p in range(min(n,10)))))
        return dict(bb),dict(su),dict(om),dict(pf),dict(ac),dict(pu)

    _pw_bbl,_pw_sub,_pw_om,_pw_pfx,_pw_ac,_pw_pu = _mk({'password'})

    print("=" * 60)
    print("TOKEN_STRIP ENHANCED v1.1 - SELF TEST")
    print("=" * 60)

    tests = [
        # (mode_name, test_func, args, expected_rules)
        ("Insert",    _extract_insert_mode,         ('paassword', base_set, 5, 4, 3),           {'i1a', 'i2a'}),
        ("Swap-k",    _extract_swap_mode,            ('apssword',  base_set, 5, 4, 3),           {'k'}),
        ("Swap-*",    _extract_swap_mode,            ('passowrd',  base_set, 5, 4, 3),           {'*45'}),
        ("Range-x",   _extract_range_mode,           ('sswor', {'password'}, 5, 4, 3, _pw_sub, _pw_om), {'x26'}),
        ("Range-O",   _extract_range_mode,           ('passd', {'password'}, 5, 4, 3, _pw_sub, _pw_om), {'O43'}),
        ("CharDup-z", _extract_char_duplicate_mode,  ('ppassword',          base_set, 5, 4),     {'z1'}),
        ("CharDup-Z", _extract_char_duplicate_mode,  ('passwordd',          base_set, 5, 4),     {'Z1'}),
        ("CharDup-q", _extract_char_duplicate_mode,  ('ppaasssswwoorrdd', {'password'}, 5, 4),   {'q'}),
        ("ASCII",     _extract_ascii_transform_mode, ('qbttxpse', {'password'}, 10, 4, 3, _pw_bbl, _pw_ac), {'+0 +1 +2 +3 +4 +5 +6 +7'}),
        ("Truncate",  _extract_truncate_mode,        ('passwor',  base_set, 5, 4, 3, _pfx),     {"'6"}),
        ("Purge",     _extract_purge_mode,           ('pssword',  base_set, 5, 4, 3, _purge),   {'@a'}),
        ("Repeat",    _extract_repeat_mode,          ('passwordpassword', base_set, 5, 4),        {'p1'}),
        ("SepTitle",  _extract_separator_title_mode, ('Pass-Word', {'pass-word'}, 5, 4, 3),      {'e-'}),
    ]

    passed = 0
    failed = 0

    for name, func, args, expected in tests:
        result = func(*args)
        if expected.issubset(result):
            print(f"  [PASS] {name:12s}: {expected}")
            passed += 1
        else:
            print(f"  [FAIL] {name:12s}: expected {expected}, got {result}")
            failed += 1

    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)
    return failed == 0

if __name__ == '__main__':
    mp.freeze_support()
    main()
