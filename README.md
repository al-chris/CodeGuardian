# CodeGuardian - ML-Powered Code Vulnerability Scanner

CodeGuardian is an advanced code security tool that helps developers identify and fix security vulnerabilities in their code using machine learning techniques.

## Features

- **Real-time Code Analysis**: Scans repositories for security issues in real-time
- **ML-Based Vulnerability Classification**: Uses machine learning to categorize and prioritize vulnerabilities
- **Intelligent Fix Suggestions**: Suggests code fixes based on detected vulnerabilities
- **Dashboard Visualization**: Interactive dashboard for monitoring and analyzing security metrics
- **CI/CD Integration**: Seamlessly integrates with modern CI/CD pipelines

## Technical Highlights

- **Machine Learning Pipeline**: Uses TensorFlow and scikit-learn to classify and prioritize vulnerabilities
- **Pattern Recognition**: Advanced pattern matching using regex and AST parsing
- **NLP for Code Analysis**: Uses NLP techniques to analyze code patterns and generate fixes
- **Distributed Architecture**: Scalable design for analyzing large codebases
- **API-First Design**: RESTful API for integration with other tools

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/codeguardian.git
cd codeguardian

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Start the server

```bash
python main.py
```

The server will start on http://localhost:8000

### API Documentation

Access the API documentation at http://localhost:8000/docs

### Sample API Requests

#### Start a new scan

```bash
curl -X POST "http://localhost:8000/scan" \
     -H "Content-Type: application/json" \
     -d '{"repository_url": "https://github.com/username/repo", "branch": "main"}'
```

#### Get scan results

```bash
curl -X GET "http://localhost:8000/scan/your-scan-id"
```

## Architecture

CodeGuardian follows a modular architecture:

1. **API Layer**: FastAPI-based REST API
2. **Core Scanner**: Code analysis engine with pattern matching and AST parsing
3. **ML Pipeline**: TensorFlow and scikit-learn based ML models
4. **Fix Generator**: Intelligent code fix suggestion system
5. **Dashboard**: Data visualization and metrics tracking

## ML Models

The system utilizes several machine learning models:

1. **Vulnerability Classifier**: Categorizes vulnerabilities by type and severity
2. **Priority Predictor**: Determines which issues need immediate attention
3. **Code Fix Generator**: Suggests fixes based on vulnerability patterns

## How It Demonstrates Advanced Skills

- **Machine Learning**: Custom ML models for code analysis
- **Security Expertise**: Demonstrates understanding of code vulnerabilities
- **Scalable System Design**: Modular architecture that can handle large codebases
- **API Design**: Well-structured RESTful API
- **Static Analysis**: Advanced code parsing and analysis
- **Testing**: Comprehensive test suite (see tests directory)

## Future Enhancements

- Integration with additional version control systems
- Support for more programming languages
- Enhanced fix generation using GPT models
- Collaborative security review features
- Extended CI/CD integrations

## License

MIT