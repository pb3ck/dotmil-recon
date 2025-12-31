# dotmil-recon

subdomain enumeration for .mil assets. built for dod vdp work.

pulls from crt.sh, checks liveness, fingerprints tech stacks, tags interesting stuff.

## install
```bash
pip install -e .
```

## usage
```bash
dotmil-recon -q "%.army.mil" --probe --live-only -o results.json
```