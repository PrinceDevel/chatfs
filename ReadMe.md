# CHATFS 

**CHATFS** is a lightning-fast, lightweight, and private real-time chat application built with Python using **FastHTML**, **Starlette**, and **SQLite**. Designed with a sleek dark-mode interface, it features instant messaging, live polling via HTMX, secure password hashing, and zero-bloat architecture.

---

## Features

* **Real-Time Messaging**: Instant updates and live thread polling using HTMX.
* **Secure Authentication**: Robust password hashing with `scrypt` and built-in brute-force protection.
* **Private & Lightweight**: Uses a self-contained SQLite backend with WAL (Write-Ahead Logging) mode enabled.
* **Responsive Dark UI**: Clean, mobile-friendly design optimized for speed and readability.

---

## Getting Started with `uv`

If you are new to **`uv`** (Astral's extremely fast Python package and project manager), follow the steps below to install it and set up the project from scratch.

### Step 1: Install `uv`

If you don't have `uv` installed on your system yet, you can install it using your system's package manager or the official standalone installer:

* **macOS / Linux:**
  ```bash
  curl -LsSf https://astral.sh/uv/install.sh | sh
  ```
* **Windows (PowerShell):**
  ```powershell
  irm https://astral.sh/uv/install.ps1 | iex
  ```

*Verify the installation:*
```bash
uv --version
```

---

### Step 2: Clone or Setup the Project

1. Navigate to your project directory containing `src` folder.
2. Initialize a new `uv` environment and install dependencies:

```bash
# Initialize a virtual environment
uv venv

# Sync The local repo
uv sync

# NOTE: Use Only If uv sync doesn't work (it should though)
uv pip install python-fasthtml fastlite 
```

---

### Step 3: Run the Application

Start the development server directly using Python or `uv`:

```bash
uv run src/main.py
```

Open your browser and navigate to **`http://localhost:5001`** (or the port specified in your console output) to register your account and start chatting!

---

## 🛠️ Project Structure

* `src`: Core application logic, database schema initialization, authentication middleware, and FastHTML routes.
* `chatfs.db`: Local SQLite database (auto-generated on first launch).
