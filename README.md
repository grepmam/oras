<p align="center">
  <img width="300" src="media/oras.png">
</p>

<div align="center">

  <a href="https://github.com/grepmam">![grepmam](https://img.shields.io/badge/Project%20from-Grepmam-red)</a>
  <a href="https://www.python.org/">![python](https://img.shields.io/badge/Written%20in-Python-green)</a>
  <a>![version](https://img.shields.io/badge/Version-1.0-yellow)</a>

</div>

OWASP Risk Assessment System is a project unofficial for calculating risk level/score of a vulnerability with a vector.

## Usage

```python
from oras import ORAS

oras = ORAS(vector="SL:1/M:9/O:0/S:2/ED:1/EE:3/A:1/ID:9/LC:6/LI:1/LAV:9/LAC:7/FD:9/RD:5/NC:2/PV:3")

print("Overall Risk Score: ", oras.calculate_overall_risk_score())
print("Overall Risk Level: ", oras.calculate_overall_risk_level())
```
