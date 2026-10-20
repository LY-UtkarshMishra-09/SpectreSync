# SpectreSync — Cybersecurity Deception & Threat Monitoring

**SpectreSync** is a cybersecurity project focused on deception-based security, synthetic honeytokens, configuration discovery, and threat monitoring. It combines Python-based tools, backend services, database persistence, and a web interface to explore how deceptive security artifacts can help identify suspicious activity.

> **Project status:** Prototype / under development. Individual components may require additional integration before they work together as a complete system.

## Overview

Traditional security tools often focus on detecting threats after suspicious activity has occurred. Deception-based security introduces controlled, artificial assets that can help reveal unauthorized access attempts and provide useful signals for investigation.

SpectreSync explores this approach by combining configuration scanning, synthetic honeytoken generation, canary-event monitoring, and security-event logging.

## Key Features

- **Configuration Discovery:** Scans a selected directory for configuration files and potential sensitive-key patterns.
- **Synthetic Honeytoken Generation:** Generates artificial tokens intended to act as deceptive security artifacts.
- **Canary Monitoring:** Provides a webhook listener for receiving events associated with monitored endpoints.
- **Threat Event Logging:** Uses SQLite-based persistence to store application or security-related records.
- **Security Dashboard:** Includes a Streamlit interface for presenting information and interacting with scanning functionality.
- **Backend API:** Includes an Express.js server for backend operations.
- **Web Interface:** Includes a Next.js application built with React and TypeScript.
- **Experimental Deception Capabilities:** Explores additional techniques, such as tarpit-style behavior, where implemented.

## How It Works

The intended workflow is:

1. **Discover:** Scan a selected directory for supported configuration files.
2. **Analyze:** Identify candidate patterns and relevant configuration data.
3. **Synthesize:** Generate artificial honeytokens for controlled security experiments.
4. **Monitor:** Receive events through the canary webhook listener.
5. **Record:** Persist relevant application or event data in a database.
6. **Review:** Use the dashboard or web interface to inspect available information.

*The exact end-to-end workflow depends on the integration and configuration of the individual components.*

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Scanning, token generation, and monitoring components |
| Streamlit | Python-based dashboard |
| Pandas | Data handling and presentation |
| Node.js | JavaScript runtime for the backend |
| Express.js | Backend server and API |
| Next.js | Web application framework |
| React | User interface components |
| TypeScript | Type-safe web development |
| FastAPI | Webhook service |
| Uvicorn | ASGI server |
| SQLite | Lightweight database persistence |
| Tailwind CSS | Web interface styling |

## Repository Structure

```text
SpectreSync/
├── app.py                  # Streamlit dashboard
├── scanner.py              # Configuration scanning
├── synthesizer.py          # Synthetic honeytoken generation
├── database.py             # SQLite persistence
├── server.js               # Express backend
├── webhook_server.py       # FastAPI canary listener
├── requirements.txt        # Python dependencies
├── package.json            # Root Node.js dependencies
├── spectresync-web/        # Next.js frontend
└── README.md               # Project documentation
```

## Getting Started

### Prerequisites

Install the following before running the project:

- Python 3.10 or later
- Node.js and npm
- Git

Check your installations:

```bash
python --version
node --version
npm --version
```

### 1. Clone the Repository

```bash
git clone https://github.com/LY-UtkarshMishra-09/SpectreSync.git
cd SpectreSync
```

### 2. Set Up the Python Environment

**Windows — PowerShell**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install streamlit pandas fastapi uvicorn
```

**Linux / macOS**

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install streamlit pandas fastapi uvicorn
```

These commands install the core Python packages referenced by the project's dashboard and webhook components. Additional dependencies may be required as the implementation evolves.

### 3. Run the Streamlit Dashboard

From the repository root:

```bash
streamlit run app.py
```

Streamlit normally makes the dashboard available at:

```text
http://localhost:8501
```

### 4. Run the Express Backend

Open a separate terminal in the repository root:

```bash
npm install
node server.js
```

The backend is configured to use port `5000` by default, subject to its actual configuration and environment.

### 5. Run the Webhook Listener

Open another terminal in the repository root and activate the Python virtual environment:

```bash
python webhook_server.py
```

The listener is configured to bind to `127.0.0.1:8000` by default, subject to its actual configuration.

### 6. Run the Next.js Frontend

Open another terminal:

```bash
cd spectresync-web
npm install
npm run dev
```

The frontend is typically available at:

```text
http://localhost:3000
```

Keep each service running in its own terminal while testing.

> **Integration note:** These commands start the individual components; they do not guarantee that all components are connected. Verify API endpoints, environment variables, database schemas, and frontend-to-backend communication before testing the complete workflow.

## Security and Responsible Use

SpectreSync is intended for authorized cybersecurity research, controlled demonstrations, and defensive testing.

- Scan only directories and systems you own or are explicitly authorized to assess.
- Use synthetic credentials and artificial honeytokens rather than real secrets.
- Do not expose webhook listeners or development servers publicly without appropriate authentication and access controls.
- Keep API keys, credentials, and sensitive configuration values out of source control.
- Test deception mechanisms only in isolated or explicitly authorized environments.
- Review logging, access controls, and data retention before using the project beyond a local prototype.

## Current Limitations

SpectreSync is a work in progress. Before treating it as an operational security platform, the following areas should be reviewed:

- Integration between the Streamlit dashboard, Express backend, webhook listener, and Next.js frontend.
- Consistency between database schemas and persistence logic.
- Dependency declarations and reproducible environment setup.
- Authentication, authorization, and validation of incoming webhook events.
- Error handling, automated tests, and security testing.
- Documentation of supported configuration formats and detection rules.

The presence of a component in the repository does not necessarily mean that the corresponding feature is fully integrated or production-ready.

## Future Improvements

Potential development directions include:

- Unified backend APIs and database schemas.
- Centralized event correlation and threat timelines.
- Improved honeytoken lifecycle management.
- Configurable alerting and event severity.
- Authentication and role-based access control.
- Automated tests and CI workflows.
- Docker-based development and deployment.
- Dashboard visualizations for security events.
- Comprehensive setup documentation and demonstration screenshots.

## Team

SpectreSync is developed by a team of five members working on cybersecurity, deception-based security, and threat monitoring.

| Team Member | Role | GitHub Profile |
|---|---|---|
| Utkarsh Mishra | Agentic A.I. Backend | [@LY-UtkarshMishra-09](https://github.com/LY-UtkarshMishra-09) |
| Bhavy Mahawar | UI/UX Developer | [@bhavymahawar](https://github.com/bhavymahawar) |
| Riya Aggarwal | Full - Stack Integration | [@riyaaggarwa](https://github.com/riyaaggarwa) |
| Tanishk Soni | Backend Security  | [@Tanishkcse777](https://github.com/Tanishkcse777) |
| Kartikey Mishra | Data Visualization | [@kartikey-svg](https://github.com/kartikey-svg) |

## Contributing

Contributions from the team are encouraged.

1. Discuss the proposed change with the team.
2. Create a separate branch for the feature or fix.
3. Make focused changes and test them locally.
4. Document any new dependencies, configuration requirements, or security implications.
5. Submit a pull request for review.

## License

This project is licensed via MIT License Policies.

## Author

**Utkarsh Mishra**  
GitHub: [LY-UtkarshMishra-09](https://github.com/LY-UtkarshMishra-09)

*SpectreSync — Exploring proactive security through deception, monitoring, and threat visibility.*