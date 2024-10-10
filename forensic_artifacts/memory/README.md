# Memory forensics (Volatility 3)

This repository does **not** ship a multi-gigabyte Windows memory dump. In a real investigation you would:

1. Capture RAM with your enterprise tool or `winpmem` / sanctioned forensic utility.
2. Run **Volatility 3** with the correct Windows symbol / kernel profile.

## Example plugins (illustrative)

```bash
vol -f memory.raw windows.pslist.PsList
vol -f memory.raw windows.pstree.PsTree
vol -f memory.raw windows.malfind.Malfind
vol -f memory.raw windows.registry.hivelist.HiveList
```

## Lab substitute

See `volatility_pslist_excerpt.txt` for **synthetic plugin-style output** matched to scenario narratives. For downloadable reference images, consult the [Volatility Foundation documentation](https://volatility3.readthedocs.io/).
