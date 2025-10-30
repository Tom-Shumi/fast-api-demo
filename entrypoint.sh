#!/bin/bash

poetry run python -m api.migrate_cloud_db
poetry run uvicorn api.main:app --host 0.0.0.0