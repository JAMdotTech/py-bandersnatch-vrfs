# py-bandersnatch-vrfs
Python Bandersnatch VRFs library utilizing the RUST [ark-ec-vrfs](https://github.com/davxy/ark-ecvrf) cryptographic library

## Installation

### Compile for local development

```
pip install -r requirements.txt
maturin develop
```
### Build wheels
```
pip install -r requirements.txt

# Build local OS wheel
maturin build --release

# Build manylinux1 wheel
docker run --rm -v $(pwd):/io ghcr.io/pyo3/maturin build --release

```
