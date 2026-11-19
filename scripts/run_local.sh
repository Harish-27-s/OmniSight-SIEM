#!/usr/bin/env bash
set -e

PROJECT_ROOT="/home/harish/PROJECTS/omnisight-siem"
cd "$PROJECT_ROOT"

# Ensure .env exists (copy from example if present)
if [ -f ".env.example" ]; then
  cp -n .env.example .env
fi

# Create virtual environment if missing
if [ ! -d "venv" ]; then
  python3 -m venv venv
fi
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Start backend
uvicorn backend.main:app --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!
echo "Backend PID $BACKEND_PID"

# Start agent collector
python -m agent.collector &
AGENT_PID=$!
echo "Agent PID $AGENT_PID"

# Start frontend (Vite)
cd frontend
npm install
npm run dev &
FRONTEND_PID=$!
echo "Frontend PID $FRONTEND_PID"

# Seed demo data after a short pause
sleep 2
source "$PROJECT_ROOT/venv/bin/activate"
python -m scripts.seed_demo

# Wait for processes (Ctrl+C to stop all)
wait $BACKEND_PID $AGENT_PID $FRONTEND_PID
