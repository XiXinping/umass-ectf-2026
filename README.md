# UMass eCTF 2026 Repo

## Build Instructions

In the parent directory, run:
```
uvx --with-editable ./ectf26_design --from ectf26_design secrets \
firmware/global.secrets 0xbeef 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16```

Then
```cd firmware```

```cargo run --release```

