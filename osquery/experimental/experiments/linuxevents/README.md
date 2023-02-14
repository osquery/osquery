# linuxevents experiment

## Notes

This is a more lightweight, container-aware version of the `bpf_process_events` table that we have in core. Note that for the time being only the `podman` container backend is recognized. If you wish to add more, reach us out in the `#ebpf` channel of the osquery Slack, pasting the output of the `cgroup_path_parts` column.

## Configuration flags

 * `--experiments_linuxevents_perf_output_size`: Perf output size (must be a power of two). Should be increased on systems with a lot of exec events.
 * `--experiments_linuxevents_circular_buffer_size`: How many rows the tables can hold before old data is overwritten.

## Tables implemented

 * `bpf_process_events_v2`
