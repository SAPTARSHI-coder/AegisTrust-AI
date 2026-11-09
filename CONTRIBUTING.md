# Contributing to AegisTrust AI

Thank you for your interest in contributing to AegisTrust AI! This project was built for the **HackMatrix** hackathon and welcomes community contributions.

## 🚀 Getting Started

1. Fork this repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/AegisTrust-AI.git`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Set up the development environment (see README.md)

## 🛠️ Development Setup

```bash
# Backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Frontend (hot-reload dev server)
cd frontend && npm install && npm run dev
```

## 📋 Areas for Contribution

- **Threat Engine**: Add new brand entries to the BRAND_REGISTRY in `threat_engine.py`
- **Scenario Vectors**: Add new realistic attack simulations in `scenarios.py`  
- **Certificate Engine**: Extend CA watchlist or add new cryptographic tests
- **Frontend**: Improve UI components, add new visualizations
- **API**: Add new endpoints or integrations (VirusTotal, OpenPhish)

## 🔀 Pull Request Guidelines

1. Keep PRs focused on a single feature or fix
2. Update README.md if you add new features
3. Test thoroughly before submitting
4. Write descriptive commit messages

## 🐛 Bug Reports

Open a GitHub Issue with:
- Description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Python/Node.js versions

---
*Built for HackMatrix | AegisTrust AI © 2026*
