# Stripper — Hashcat Rule Extractor (Enhanced v1.1)

Stripper empirically derives [hashcat](https://hashcat.net/hashcat/) rule chains by
decomposing passwords in a **target** wordlist into transformations of stems found in a
**base** wordlist. Instead of hand-writing rules, you feed it real base/target password
pairs and it works out the rule chain that turns one into the other — then writes the
result as a standard hashcat `.rule` file.

This is a standalone, multiprocessing-enabled extraction of the rule engine from
`rulest_v2`, so it can run on CPU alone (no GPU required).

## What it does

For every word in the target list, Stripper tries to find a matching stem in the base
list and reconstruct the target from that stem using one or more hashcat rule
operations. It supports 14 extraction modes:

| Mode | Rule syntax | Detects |
|---|---|---|
| Letter | — | Stem = letters (+leet), boundary = digits/specials |
| Digit | — | Stem = pure digit run, boundary = letters/specials |
| Reverse | `r` | Reversed stems |
| Delete-edge | `[` / `]` | Leading/trailing character deletion |
| Duplicate/Fold | `d` / `f` | Word duplication or case-folding |
| Insert | `iNX` | Character inserted at position N |
| Swap | `*MN`, `k`, `K` | Transpositions (adjacent or positional) |
| Range Extract/Omit | `xNM`, `ONM` | Contiguous substring extraction or omission |
| Char-Duplicate | `zN`, `ZN`, `q` | First/last/all character duplication |
| ASCII Transform | `+N`, `-N`, `LN`, `RN`, `.N`, `,N` | Single-character ASCII offsets/shifts |
| Truncate | `'N` | Position-based truncation |
| Purge | `@X` | Removal of all instances of a character |
| Repeat | `pN` | Whole-word repetition |
| Separator Title-Case | `eX` | Title-casing split on a custom separator |

It also independently generates **toggle-chain seeds** (case-toggle patterns at each
position, combined with leet substitutions) and appends them to the output.

Rules that are redundant, malformed, or known to be ineffective are filtered out via
`should_exclude_rule`, and all generated rules are validated against hashcat's rule
grammar (`HashcatRuleValidator`) before being written out.

## Requirements

- Python 3.8+
- [`tqdm`](https://pypi.org/project/tqdm/)
- `colorama` (optional, for colored output on Windows terminals)

```bash
pip install tqdm colorama
```

## Usage

```bash
python stripper.py BASE TARGET [options]
```

**Positional arguments**

| Argument | Description |
|---|---|
| `BASE` | Base wordlist — candidate stems |
| `TARGET` | Target wordlist — passwords to decompose |

**Output**

| Flag | Default | Description |
|---|---|---|
| `-o`, `--output FILE` | `stripper_rules.txt` | Rule output file |

**Extraction tuning**

| Flag | Default | Description |
|---|---|---|
| `--max-depth N` | `0` (unlimited, capped at 31) | Maximum rule chain length |
| `--min-stem N` | `4` | Minimum stem length to consider |
| `--leet-amb N` | `3` | Max ambiguous leet-substitution positions |
| `--no-toggle-seeds` | off | Skip toggle-chain seed generation |
| `--no-new-modes` | off | Skip all v1.1 extraction modes (insert, swap, range, etc.) |
| `--ascii-range N` | `3` | Max ASCII offset considered for the ASCII transform mode |

**Parallelism**

| Flag | Default | Description |
|---|---|---|
| `--workers N` | CPU count | Number of worker processes |
| `--chunk-size N` | auto | Words per worker chunk |

**Misc**

| Flag | Description |
|---|---|
| `--debug` | Verbose debug output |

### Example

```bash
python stripper.py base_wordlist.txt breached_passwords.txt \
  -o derived.rule \
  --min-stem 4 \
  --max-depth 6 \
  --workers 8
```

This scans `breached_passwords.txt`, tries to match each password to a stem in
`base_wordlist.txt`, and writes the resulting hashcat rule chains to `derived.rule`.
Use the result with hashcat as a normal rule file:

```bash
hashcat -a 0 -m <hash-mode> hashes.txt base_wordlist.txt -r derived.rule
```

## Output format

The output is a standard hashcat rules file: one rule chain per line, with a header
comment block summarizing the run (timestamp, inputs, depth, worker count, rule counts
by depth and by mode).

## Self-test

The script includes a built-in self-test that exercises each extraction mode against
known input/output pairs:

```bash
python -c "import stripper; stripper._self_test()"
```
- Rule chains longer than hashcat's 31-operation limit are not generated.
- `--no-new-modes` restricts extraction to the original five modes (letter, digit,
  reverse, delete-edge, duplicate/fold) if you want v1.0-equivalent behavior.
