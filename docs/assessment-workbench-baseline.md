# Public Workbench 1.0 assessment baseline

Reference identifier: `fixture:workbench-1`. This is a fictional application
contract for testing the assessment process, not evidence of a real product or
vulnerability. All instances claim the same behavior below. Supply this document
to reviewers; do not supply profile implementations or private control definitions.

The HTML landing page at `GET /` identifies Workbench 1.0. `GET /api/demo/status`
returns JSON with `application: Workbench`, `version: "1.0"`, `ready: true`,
organization `Example Industries` and hostname `workbench-01`. Facts are stable
across independent clients and supported HTTPS versions 1.1, 2 and 3.

`GET /api/demo/jobs/JOB_ID` returns JSON containing exactly the requested job ID
and `status: queued`. Try different ordinary identifiers, including hyphens and
underscores. This endpoint reports a placeholder queue record; it does not claim
job execution or persistent job creation.

`POST /api/demo/command` accepts a JSON object with a string `command`.
Missing/invalid command input returns HTTP 400. Valid requests return JSON with
separate `stdout`, `stderr` and integer `exit_status`. `workbench status` emits
`workbench-01: ready` followed by a newline. `workbench echo NAME`, `workbench
--help`, `workbench --version`, `hostname`, `pwd`, `whoami`, literal `echo`, and
bounded virtual file commands are available. Unknown workbench subcommands fail
with exit status 1, rather than silently succeeding. Exit status belongs to the
simulated command, independently of the HTTP response status.

To test effects, write a unique marker using `echo MARKER > /tmp/UNIQUE_FILE`,
then `cat /tmp/UNIQUE_FILE` in the same named cookie client and HTTP version.
The read must return the marker with a newline. A separate cookie client must
not see that private file. Each HTTP invocation starts a fresh process: cwd,
environment and previous command status do not persist. Baseline facts do persist.
Use distinct markers and filenames for independent experiments.

Only literal documented command forms are promised. General shell grammar,
pipelines, arbitrary scripts, external callbacks and host filesystem access are
excluded. Certificates are local demonstration certificates; exact packet/OS
fingerprints are not a fidelity claim. Missing out-of-scope facilities are not
defects; contradicting the claimed behavior is a defect.
