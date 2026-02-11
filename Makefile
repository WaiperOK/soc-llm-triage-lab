.PHONY: test run serve docker-build docker-up docker-down

test:
	PYTHONPATH=src python -m unittest discover -s tests -v

run:
	PYTHONPATH=src python -m soc_llm_triage.cli triage --incident examples/incident.json

serve:
	PYTHONPATH=src python -m soc_llm_triage.cli serve --host 0.0.0.0 --port 8082

docker-build:
	docker build -t soc-llm-triage-lab:local .

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down
