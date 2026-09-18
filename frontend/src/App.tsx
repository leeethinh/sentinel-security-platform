import { useEffect, useState } from 'react'
import './App.css'

type SecurityFinding = {
  type: string
  severity: string
  message: string
}

type UrlScanResult = {
  url: string
  reachable: boolean
  https: boolean
  statusCode: number
  responseTimeMs: number
  findings: SecurityFinding[]
}
type FileScanResult = {
  fileName: string
  sizeBytes: number
  contentType: string | null
  sha256: string | null
  findings: SecurityFinding[]
}
type ScanHistoryItem = {
  id: number
  scanType: string
  target: string
  severity: string
  scannedAt: string
}
function App() {
  const [url, setUrl] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [fileResult, setFileResult] =
      useState<FileScanResult | null>(null)

  const [fileLoading, setFileLoading] =
      useState(false)

  const [fileError, setFileError] =
      useState('')

  const [urlResult, setUrlResult] =
      useState<UrlScanResult | null>(null)

  const [urlLoading, setUrlLoading] =
      useState(false)

  const [urlError, setUrlError] =
      useState('')

  const [history, setHistory] =
      useState<ScanHistoryItem[]>([])
  const loadHistory = async () => {
    try {
      const response = await fetch(
          'http://localhost:8080/api/scans/history'
      )

      if (!response.ok) {
        throw new Error('Could not load history')
      }

      const data: ScanHistoryItem[] =
          await response.json()

      setHistory(data)

    } catch (error) {
      console.error('Failed to load scan history')
    }
  }
  useEffect(() => {
    loadHistory()
  }, [])

  const analyzeUrl = async () => {
    if (!url.trim()) {
      return
    }

    setUrlLoading(true)
    setUrlError('')
    setUrlResult(null)

    try {
      const response = await fetch(
          'http://localhost:8080/api/scans/url',
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              url: url,
            }),
          }
      )

      if (!response.ok) {
        throw new Error('URL analysis failed')
      }

      const data: UrlScanResult = await response.json()

      setUrlResult(data)
      await loadHistory()

    } catch (error) {
      setUrlError(
          'Sentinel could not complete the URL analysis.'
      )
    } finally {
      setUrlLoading(false)
    }
  }
  const analyzeFile = async () => {
    if (!file) {
      return
    }

    setFileLoading(true)
    setFileError('')
    setFileResult(null)

    try {
      const formData = new FormData()

      formData.append('file', file)

      const response = await fetch(
          'http://localhost:8080/api/scans/file',
          {
            method: 'POST',
            body: formData,
          }
      )

      if (!response.ok) {
        throw new Error('File analysis failed')
      }

      const data: FileScanResult =
          await response.json()

      setFileResult(data)
      await loadHistory()

    } catch (error) {
      setFileError(
          'Sentinel could not complete the file analysis.'
      )
    } finally {
      setFileLoading(false)
    }
  }

  return (
      <div className="app">

        <header className="header">
          <div>
            <h1>Sentinel</h1>
            <p>Web & File Security Analysis Platform</p>
          </div>

          <div className="status">
            <span className="status-dot"></span>
            System Online
          </div>
        </header>

        <main className="container">

          <section className="hero">
            <p className="eyebrow">
              SECURITY ANALYSIS
            </p>

            <h2>Analyze potential threats.</h2>

            <p className="hero-description">
              Inspect URLs and files using security analysis,
              cryptographic hashing, and threat intelligence.
            </p>
          </section>

          <div className="scanner-grid">

            {/* URL SCANNER */}
            <section className="card">

              <div className="card-number">
                01
              </div>

              <h3>URL Analysis</h3>

              <p>
                Analyze a website for security indicators and
                reputation data.
              </p>

              <input
                  type="text"
                  placeholder="https://example.com"
                  value={url}
                  onChange={(event) =>
                      setUrl(event.target.value)
                  }
              />

              <button
                  onClick={analyzeUrl}
                  disabled={urlLoading || !url.trim()}
              >
                {urlLoading
                    ? 'Analyzing...'
                    : 'Analyze URL'}
              </button>

              {/* ERROR */}
              {urlError && (
                  <div className="result error-result">
                    <strong>Analysis Error</strong>
                    <p>{urlError}</p>
                  </div>
              )}

              {/* URL RESULT */}
              {urlResult && (() => {

                const threatFinding =
                    urlResult.findings.find(
                        finding =>
                            finding.type === 'THREAT_ANALYSIS'
                    )

                const otherFindings =
                    urlResult.findings.filter(
                        finding =>
                            finding.type !== 'THREAT_ANALYSIS'
                    )

                return (
                    <div className="result">

                      {/* RESULT HEADER */}
                      <div className="result-header">

                        <strong>
                          Analysis Result
                        </strong>

                        <span
                            className={
                              urlResult.reachable
                                  ? 'badge success'
                                  : 'badge warning'
                            }
                        >
                      {urlResult.reachable
                          ? 'REACHABLE'
                          : 'UNREACHABLE'}
                    </span>

                      </div>

                      {/* THREAT ANALYSIS - ALWAYS FIRST */}
                      {threatFinding && (
                          <div className="findings">

                            <div className="finding">

                              <div>
                                <strong>
                                  Threat Analysis
                                </strong>

                                <span
                                    className={
                                      `severity ${threatFinding.severity.toLowerCase()}`
                                    }
                                >
                            {threatFinding.severity}
                          </span>
                              </div>

                              <p>
                                {threatFinding.message}
                              </p>

                            </div>

                          </div>
                      )}

                      {/* TECHNICAL DETAILS */}
                      <div className="result-stats">

                        <div>
                          <span>HTTPS</span>

                          <strong>
                            {urlResult.https
                                ? 'Yes'
                                : 'No'}
                          </strong>
                        </div>

                        <div>
                          <span>Status</span>

                          <strong>
                            {urlResult.statusCode || 'N/A'}
                          </strong>
                        </div>

                        <div>
                          <span>Response</span>

                          <strong>
                            {urlResult.responseTimeMs} ms
                          </strong>
                        </div>

                      </div>

                      {/* OTHER SECURITY FINDINGS - BOTTOM */}
                      {otherFindings.length > 0 && (
                          <div className="findings">

                            {otherFindings.map(
                                (finding, index) => (

                                    <div
                                        className="finding"
                                        key={index}
                                    >

                                      <div>

                                        <strong>
                                          {finding.type
                                              .split('_')
                                              .map(
                                                  word =>
                                                      word
                                                          .charAt(0)
                                                          .toUpperCase() +
                                                      word
                                                          .slice(1)
                                                          .toLowerCase()
                                              )
                                              .join(' ')}
                                        </strong>

                                        <span
                                            className={
                                              `severity ${finding.severity.toLowerCase()}`
                                            }
                                        >
                                {finding.severity}
                              </span>

                                      </div>

                                      <p>
                                        {finding.message}
                                      </p>

                                    </div>

                                )
                            )}

                          </div>
                      )}

                    </div>
                )
              })()}

            </section>

            {/* FILE SCANNER */}
            <section className="card">

              <div className="card-number">
                02
              </div>

              <h3>File Analysis</h3>

              <p>
                Calculate a SHA-256 fingerprint and check known
                threat intelligence.
              </p>

              <label className="file-input">

                <input
                    type="file"
                    onChange={(event) =>
                        setFile(
                            event.target.files?.[0] ?? null
                        )
                    }
                />

                {file
                    ? file.name
                    : 'Choose a file'}

              </label>

              <button
                  onClick={analyzeFile}
                  disabled={!file || fileLoading}
              >
                {fileLoading
                    ? 'Analyzing...'
                    : 'Analyze File'}
              </button>
              {fileError && (
                  <div className="result error-result">
                    <strong>Analysis Error</strong>
                    <p>{fileError}</p>
                  </div>
              )}

              {fileResult && (() => {

                const threatFinding =
                    fileResult.findings.find(
                        finding =>
                            finding.type === 'THREAT_ANALYSIS'
                    )

                const otherFindings =
                    fileResult.findings.filter(
                        finding =>
                            finding.type !== 'THREAT_ANALYSIS'
                    )

                return (
                    <div className="result">

                      <div className="result-header">
                        <strong>Analysis Result</strong>

                        <span className="badge success">
          COMPLETE
        </span>
                      </div>

                      {/* Threat analysis first */}
                      {threatFinding && (
                          <div className="findings">
                            <div className="finding">

                              <div>
                                <strong>Threat Analysis</strong>

                                <span
                                    className={`severity ${threatFinding.severity.toLowerCase()}`}
                                >
                {threatFinding.severity}
              </span>
                              </div>

                              <p>{threatFinding.message}</p>

                            </div>
                          </div>
                      )}

                      {/* File information */}
                      <div className="file-details">

                        <div>
                          <span>FILE</span>
                          <strong>{fileResult.fileName}</strong>
                        </div>

                        <div>
                          <span>SIZE</span>
                          <strong>
                            {(fileResult.sizeBytes / 1024).toFixed(2)} KB
                          </strong>
                        </div>

                        <div>
                          <span>TYPE</span>
                          <strong>
                            {fileResult.contentType || 'Unknown'}
                          </strong>
                        </div>

                      </div>


                      {/* Other findings */}
                      {otherFindings.length > 0 && (
                          <div className="findings other-findings">

                            {otherFindings.map((finding, index) => (
                                <div
                                    className="finding"
                                    key={index}
                                >
                                  <div>
                                    <strong>
                                      {finding.type
                                          .split('_')
                                          .map(
                                              word =>
                                                  word.charAt(0).toUpperCase() +
                                                  word.slice(1).toLowerCase()
                                          )
                                          .join(' ')}
                                    </strong>

                                    <span
                                        className={`severity ${finding.severity.toLowerCase()}`}
                                    >
                  {finding.severity}
                </span>
                                  </div>

                                  <p>{finding.message}</p>
                                </div>
                            ))}

                          </div>
                      )}

                    </div>
                )
              })()}
            </section>

          </div>

          {/* HISTORY */}
          <section className="history">

            <div className="section-heading">

              <div>
                <p className="eyebrow">
                  ACTIVITY
                </p>

                <h3>Recent Scans</h3>
              </div>

              <span>
              {history.length} {history.length === 1 ? 'scan' : 'scans'}
              </span>

            </div>

            {history.length === 0 ? (
                <div className="empty-state">
                  <p>No scans yet.</p>
                </div>
            ) : (
                <div className="history-list">

                  {history.map((scan) => (
                      <div
                          className="history-item"
                          key={scan.id}
                      >
                        <div className="history-type">
                          <span>{scan.scanType}</span>

                          <strong>{scan.target}</strong>
                        </div>

                        <div className="history-meta">
          <span
              className={`severity ${scan.severity.toLowerCase()}`}
          >
            {scan.severity}
          </span>

                          <span className="history-date">
            {new Date(scan.scannedAt).toLocaleString()}
          </span>
                        </div>
                      </div>
                  ))}

                </div>
            )}

          </section>

        </main>

      </div>
  )
}

export default App