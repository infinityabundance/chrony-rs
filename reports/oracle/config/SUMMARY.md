# Config oracle differential (2026-06-14T17:13:19Z)

Oracle: `chronyd (chrony) version 4.5 (+CMDMON +NTP +REFCLOCK +RTC +PRIVDROP +SCFILTER +SIGND +ASYNCDNS +NTS +SECHASH +IPV6 -DEBUG)`

| Fixture | chrony exit | chrony-rs exit | accept agree | chrony diagnostic (normalized) |
|---------|------------:|---------------:|:------------:|--------------------------------|
| err_driftfile_no_path.conf | 1 | 1 | yes | `Fatal error : Missing arguments for driftfile directive at line 1 in file <FILE>` |
| err_makestep_bad_number.conf | 1 | 1 | yes | `Fatal error : Could not parse makestep directive at line 1 in file <FILE>` |
| err_rtcsync_extra_args.conf | 1 | 1 | yes | `Fatal error : Too many arguments for rtcsync directive at line 1 in file <FILE>` |
| err_server_no_address.conf | 1 | 1 | yes | `Fatal error : Could not parse server directive at line 1 in file <FILE>` |
| err_unknown_directive.conf | 1 | 1 | yes | `Fatal error : Invalid directive at line 1 in file <FILE>` |
| valid_comments.conf | 0 | 0 | yes | `(none)` |
| valid_minimal.conf | 0 | 0 | yes | `(none)` |

Disagreements on accept/reject: 0
