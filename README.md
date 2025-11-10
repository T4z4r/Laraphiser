# 🚀 LaraPhiser v2.2

A Python-based Laravel OWASP Scanner for detecting security vulnerabilities in Laravel applications. Crafted by T4Z4r.

LaraPhiser is a comprehensive security scanning tool specifically designed for Laravel projects. It scans for OWASP Top 10 vulnerabilities using regex patterns, integrates with external tools like Bandit, Psalm, and PHPStan, and provides a user-friendly GUI for easy operation.

## Features

- **OWASP Top 10 Coverage**: Scans for vulnerabilities across all 10 OWASP categories (A01-A10).
- **Intensity Levels**: Choose from Normal, Medium, or Hard scan depths for each category.
- **Laravel-Specific Rules**: Over 15 custom regex patterns tailored for Laravel security issues.
- **External Tool Integration**: Supports Bandit (Python), Psalm, and PHPStan for enhanced analysis.
- **GUI Interface**: Built with Tkinter for an intuitive desktop application experience.
- **Drag-and-Drop Support**: Easily select project folders via drag-and-drop.
- **Export Reports**: Generate detailed HTML reports of scan results.
- **File Exclusion**: Option to exclude specific file types from scanning.

## Files

- `main.py`: The main entry point for the application (v2.2).
- `laraphiser.py`: An earlier version of the scanner (v2.0).

## Installation

1. Ensure you have Python installed (version 3.6 or higher recommended).
2. Clone or navigate to the project directory.
3. Install required dependencies:
   ```
   pip install bandit colorama tqdm tkinterdnd2
   ```
4. Optionally, set up a virtual environment:
   ```
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

## Usage

### Running the Application

Launch the GUI scanner:
```
python main.py
```

This will open a desktop window with the LaraPhiser interface.

### How to Use

1. **Select a Folder**: Click "Select Folder" or drag-and-drop a Laravel project directory into the application.
2. **Configure OWASP Categories**: Click "OWASP & Intensity" to select which OWASP Top 10 categories to scan (e.g., A01: Broken Access Control) and set the intensity level (Normal, Medium, Hard).
3. **Exclude File Types** (Optional): Click "Exclude Files" to skip scanning certain extensions (e.g., .css, .js, images).
4. **Start the Scan**: Click "Start Scan" to begin the security analysis. The progress bar will show the scan status.
5. **View Results**: Issues are displayed in a tree view, grouped by OWASP category. Double-click on an issue to open the file in your default editor.
6. **Export Report**: Click "Export HTML" to save a detailed report in HTML format.
7. **Stop or Clear**: Use "Stop Scan" to cancel an ongoing scan or "Clear" to reset the log.

### Scan Details

- **Supported File Types**: Scans .php, .blade.php, .env, .js, .json, .yml, .yaml, .sql, .html, and artisan files.
- **Exclusions**: By default, excludes vendor, node_modules, storage, bootstrap, and .git directories.
- **Intensity Levels**:
  - **Normal**: Basic checks.
  - **Medium**: Additional patterns and rules.
  - **Hard**: Full set of rules, including runtime checks (e.g., file permissions) and external tool integrations.
- **External Tools**: If installed, integrates with Bandit for Python security, Psalm/PHPStan for PHP static analysis.

### Example Output

The scanner will log issues like:
- Mass assignment vulnerabilities in models.
- Hardcoded secrets in .env files.
- SQL injection risks in queries.
- Missing CSRF protection in forms.

Reports include file paths, line numbers, severity levels (HIGH, MEDIUM, LOW), and code snippets.

## Contributing

Feel free to contribute by submitting issues or pull requests. For suggestions or bugs, please open an issue on the repository.

## License

This project is open-source. Check for a LICENSE file if applicable.