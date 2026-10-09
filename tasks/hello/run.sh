#!/bin/bash
# The example task (router/tasks.go, machine/task.go). PARAM_<FIELD> and TASK_PARAMS hold the values (not
# secret); the line's stores are in the env; TASK_STATE_DIR survives between runs; TASK_OUTPUT is the run's
# result shown in the app.
set -euo pipefail
n=$(( $(cat "$TASK_STATE_DIR/runs" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$TASK_STATE_DIR/runs"
echo "hello: ${PARAM_MESSAGE} (run $n of instance ${TASK_INSTANCE:-?}, trigger ${TASK_TRIGGER:-?})"
echo "run $n: ${PARAM_MESSAGE}" > "$TASK_OUTPUT"
[ "${PARAM_FAIL:-false}" = "true" ] && { echo "failing as asked" >&2; exit 1; }
exit 0
