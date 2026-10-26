# alert2case

SOC alert-to-case automation (Layihə 3).

## Başlamaq
1. Phase 0 hazırlığı: `tools/doctor.sh` hamısı OK olmalıdır
2. `uv venv --python 3.12 && source .venv/bin/activate`
3. `uv pip install -r requirements-dev.txt`
4. `pre-commit install`

## Struktur
app/  rules/  dataset/  n8n/  tests/  tools/  docs/
