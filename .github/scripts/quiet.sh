# Sourced by the workflows. This repository is public, and so are its Actions logs, but the
# source it builds is not: compiler warnings and errors quote source lines. So build and test
# output goes to a file on the runner (which is discarded with it), and the log only shows
# whether each command worked. On failure it shows the error and test-failure headlines (file,
# line, error code, test name), never the quoted source. Reproduce failures locally.

# quiet <name> <command...>
quiet() {
  local name=$1
  shift
  local log="$RUNNER_TEMP/quiet-${name// /-}.log"
  local started=$SECONDS
  local status=0
  "$@" > "$log" 2>&1 || status=$?
  if [ "$status" -eq 0 ]; then
    echo "$name: ok ($((SECONDS - started))s)"
    return 0
  fi
  echo "::error::$name failed (exit $status). The full output isn't shown because this log is public. Run the same command locally."
  grep -E \
    -e '^error(\[E[0-9]+\])?: ' \
    -e '^ +--> ' \
    -e '^test .+ \.\.\. FAILED$' \
    -e "^thread '.+' panicked at " \
    -e '^ *(FAIL|×) ' \
    -e 'error TS[0-9]+:' \
    -e '^npm (ERR!|error) (code|errno|syscall|path) ' \
    -e '^Error: (Command failed|cannot)' \
    "$log" | cut -c1-200 | head -n 60 || true
  return "$status"
}
