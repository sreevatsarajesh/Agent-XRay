.PHONY: test backend frontend

test:
	cd backend && python -m unittest -v test_scanner

backend:
	cd backend && uvicorn main:app --reload --port 8000

frontend:
	cd frontend && npm run dev
