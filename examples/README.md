# Synthetic examples

Generate a fresh example from the project root:

```sh
python -m p1qr demo --output demo_output
```

Open `demo_output/credential.png` for a labelled presentation image. The directory
also contains `credential.p1qr`, `public_key.pem`, and `manifest.json`. The manifest
records a public-key fingerprint and the synthetic-only limitation. It is not a trust
anchor. Private keys are never exported.

The default `python -m p1qr demo` uses temporary storage and removes it afterward.
Existing output directories are refused. Choose a new directory for another retained
demo. Do not add real Aadhaar material to this directory or the repository.

