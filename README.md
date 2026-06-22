# Mushroom Detector

A modern React + Flask computer-vision mushroom risk prediction demo with register/login authentication.

> Safety: this app is educational software only. Never eat wild mushrooms based on an app prediction.

## Project structure

- `backend/` Flask API with SQLite users, hashed passwords, bearer sessions, image validation, and CV-style prediction scoring
- `frontend/` Vite React UI with landing page, login, register, logout, camera/upload scanning, and protected prediction calls

## Run the Flask API

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

The API runs at `http://localhost:5000`.

## Run the React app

```bash
cd frontend
npm install
npm run dev
```

Open the Vite URL, usually `http://localhost:5173`.

If your API runs elsewhere, set:

```bash
VITE_API_BASE_URL=http://localhost:5000 npm run dev
```

## API endpoints

- `GET /api/health`
- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `GET /api/options`
- `POST /api/predict` — multipart image upload, requires `Authorization: Bearer <token>`

SQLite data is stored by default at `backend/mushroom_detector.db`. Override with `MUSHROOM_DB_PATH=/path/to/file.db`.

To use your trained Keras classifier, place it at `backend/model/mushroom_classifier.keras` or set:

```bash
MUSHROOM_MODEL_PATH="/path/to/mushroom_classifier.keras" python app.py
```

The API relies solely on the Keras model. If the model is missing or cannot load, prediction returns an error instead of using a fallback. Low-confidence model outputs return `scan_failed` so random non-mushroom objects are not treated as edible. Configure the threshold with `MUSHROOM_MIN_CONFIDENCE`; default is `85`. The backend requirements use `tensorflow-cpu` so the app runs on CPU-only machines without CUDA/NVIDIA setup.
# mushroom-detection
# mushroom-detection
