#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_FILE="${ROOT_DIR}/web_app.py"
RUN_DIR="${ROOT_DIR}/.run"
LOG_DIR="${ROOT_DIR}/logs"
PID_FILE="${RUN_DIR}/translator.pid"
LOG_FILE="${LOG_DIR}/translator.log"
PORT="${PORT:-5008}"
HOST="${HOST:-0.0.0.0}"
WORKERS="${WORKERS:-4}"

if [[ -x "${ROOT_DIR}/venv/bin/python" ]]; then
  DEFAULT_PYTHON="${ROOT_DIR}/venv/bin/python"
  VENV_BIN="${ROOT_DIR}/venv/bin"
else
  DEFAULT_PYTHON="python3"
  VENV_BIN=""
fi
PYTHON_BIN="${PYTHON_BIN:-${DEFAULT_PYTHON}}"

mkdir -p "${RUN_DIR}" "${LOG_DIR}" "${ROOT_DIR}/memory_data" "${ROOT_DIR}/cache_data"

is_running() {
  if [[ -f "${PID_FILE}" ]]; then
    local pid
    pid="$(cat "${PID_FILE}")"
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      return 0
    fi
    rm -f "${PID_FILE}"
  fi
  return 1
}

health_check_url() {
  local url="http://${HOST}:${PORT}/healthz"
  curl -sf --noproxy '*' --max-time 3 "${url}" >/dev/null 2>&1
}

start_service() {
  if is_running; then
    echo "translator already running (pid=$(cat "${PID_FILE}"))"
    return 0
  fi

  local use_gunicorn
  use_gunicorn=false
  if [[ -n "${VENV_BIN}" && -x "${VENV_BIN}/gunicorn" ]]; then
    GUNICORN="${VENV_BIN}/gunicorn"
    use_gunicorn=true
  elif command -v gunicorn &>/dev/null; then
    GUNICORN="gunicorn"
    use_gunicorn=true
  fi

  echo "starting translator service..."
  rm -f "${PID_FILE}"

  local env_block
  env_block="PORT=${PORT} HOST=${HOST} PYTHONPATH=${ROOT_DIR}"

  if [[ "${use_gunicorn}" == true ]]; then
    echo "  using gunicorn (workers=${WORKERS})"
    (
      cd "${ROOT_DIR}"
      env ${env_block} "${GUNICORN}" \
        -w "${WORKERS}" \
        -b "${HOST}:${PORT}" \
        --timeout 120 \
        --access-logfile "${LOG_DIR}/access.log" \
        --error-logfile "${LOG_DIR}/error.log" \
        --pid "${PID_FILE}" \
        --daemon \
        "web_app:app"
    )
    sleep 0.5
    # gunicorn --daemon writes pid file asynchronously
    if [[ -f "${PID_FILE}" ]]; then
      # ensure the pid file is fully written
      sleep 0.3
    fi
  else
    echo "  using flask dev server (install gunicorn for production)"
    (
      cd "${ROOT_DIR}"
      nohup env ${env_block} "${PYTHON_BIN}" "${APP_FILE}" >> "${LOG_FILE}" 2>&1 &
      echo $! > "${PID_FILE}"
    )
  fi

  # wait up to 8s for startup
  local retries=16
  while (( retries-- > 0 )); do
    if health_check_url; then
      echo "started (pid=$(cat "${PID_FILE}"), port=${PORT}, host=${HOST})"
      echo "log: ${LOG_FILE}"
      return 0
    fi
    sleep 0.5
  done

  # startup timeout — clean up
  if is_running; then
    local pid; pid="$(cat "${PID_FILE}")"
    kill "${pid}" 2>/dev/null || true
    rm -f "${PID_FILE}"
  fi
  echo "failed to start within 8s, check log: ${LOG_FILE}"
  return 1
}

stop_service() {
  if ! is_running; then
    echo "translator not running"
    return 0
  fi

  local pid
  pid="$(cat "${PID_FILE}")"
  echo "stopping translator (pid=${pid})..."

  kill "${pid}" 2>/dev/null || true

  local retries=10
  while (( retries-- > 0 )); do
    if kill -0 "${pid}" 2>/dev/null; then
      sleep 1
    else
      break
    fi
  done

  if kill -0 "${pid}" 2>/dev/null; then
    echo "force killing pid=${pid}"
    kill -9 "${pid}" 2>/dev/null || true
    sleep 0.5
  fi

  rm -f "${PID_FILE}"
  echo "stopped"
}

status_service() {
  if is_running; then
    local pid
    pid="$(cat "${PID_FILE}")"
    echo "pid:      ${pid}"
    echo "port:     ${PORT}"
    echo "host:     ${HOST}"
    echo "workdir:  ${ROOT_DIR}"
    echo "log:      ${LOG_FILE}"

    # port check
    if command -v ss &>/dev/null; then
      local port_info
      port_info="$(ss -tlnp 2>/dev/null | grep ":${PORT} " || true)"
      if [[ -n "${port_info}" ]]; then
        echo "listen:   ${port_info}"
      else
        echo "listen:   NOT FOUND on :${PORT}"
      fi
    fi

    # healthz
    local hz_url="http://${HOST}:${PORT}/healthz"
    if curl -sf --noproxy '*' --max-time 3 "${hz_url}" >/dev/null 2>&1; then
      echo "healthz:  OK"
    else
      echo "healthz:  FAIL"
    fi

    # readyz
    local rz_url="http://${HOST}:${PORT}/readyz"
    local rz_out
    if rz_out="$(curl -sf --noproxy '*' --max-time 3 "${rz_url}" 2>/dev/null)"; then
      local rz_status
      rz_status="$(echo "${rz_out}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','?'))" 2>/dev/null || echo "?")"
      echo "readyz:   ${rz_status}"
    else
      echo "readyz:   FAIL"
    fi

    # version
    local ver_url="http://${HOST}:${PORT}/api/version"
    local ver_out
    if ver_out="$(curl -sf --noproxy '*' --max-time 3 "${ver_url}" 2>/dev/null)"; then
      local ver_info
      ver_info="$(echo "${ver_out}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f\"v={d.get('version','?')} analyzers={d.get('analyzers','?')} features={d.get('features','?')}\")" 2>/dev/null || echo "?")"
      echo "version:  ${ver_info}"
    else
      echo "version:  FAIL"
    fi

    return 0
  else
    echo "stopped"
    return 1
  fi
}

restart_service() {
  stop_service
  sleep 1
  start_service
}

tail_log() {
  touch "${LOG_FILE}"
  tail -n 100 -f "${LOG_FILE}"
}

usage() {
  cat <<EOF
Usage: $0 {start|stop|restart|status|logs}

Subcommands:
  start     Start the translator service
  stop      Gracefully stop the translator service
  restart   Stop then start
  status    Show service status (pid, port, healthz, readyz, version)
  logs      Tail the main log file

Environment variables:
  PORT         listen port (default: 5008)
  HOST         listen host (default: 0.0.0.0)
  WORKERS      gunicorn worker count (default: 4)
  PYTHON_BIN   python executable (default: venv/bin/python or python3)

Required for LLM translation:
  LLM_API_KEY  API key for the LLM provider
  LLM_MODEL    model name (default: MiniMax-M2.7)
  LLM_BASE_URL LLM API base URL

Optional API authentication:
  API_SECRET   if set, all API routes require X-API-Secret header
EOF
}

cmd="${1:-}"
case "${cmd}" in
  start)   start_service ;;
  stop)    stop_service ;;
  restart) restart_service ;;
  status)  status_service ;;
  logs)    tail_log ;;
  *)       usage; exit 1 ;;
esac
