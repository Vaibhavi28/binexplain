# BinExplain

A monorepo containing the **backend** (Python) and **frontend** (React) for BinExplain.

## Project Structure

```
binexplain/
├── backend/          # Python backend (Flask / FastAPI)
│   ├── main.py
│   ├── requirements.txt
│   └── .gitignore
├── frontend/         # React frontend (Vite)
│   ├── src/
│   ├── package.json
│   └── .gitignore
├── README.md
└── .gitignore
```

## Getting Started

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

## Rules

- Backend and frontend are **completely independent** — changing one should never break the other.
- Each has its own `.gitignore` and dependency files.
- **No uploaded binary files** should ever be committed in either folder.