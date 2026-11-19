# UMass eCTF 2026 Repo

## Build Instructions
Make sure you have [uv](https://astral.sh/uv) installed.
Additionally, follow the instructions to setup [HSF-client](https://github.com/NoahW227).


In the parent directory, run:
```
uvx --with-editable ./ectf26_design --from ectf26_design secrets \
firmware/global.secrets 0xbeef 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16
```

Then run:

```cd firmware```

To build and run the Rust firmware, run:


```cargo run --release```

