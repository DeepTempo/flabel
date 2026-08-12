##! JSON log filters for `conn` and `ssl`, added alongside Zeek's default TSV logs.
##!
##! flabel retains the TSV logs and parses the JSON ones, and both are written by the same
##! analysis pass — so the retained artifact and the parsed input cannot disagree about a
##! flow (`docs/spec.md` §8). The alternative, a second Zeek run with `LogAscii::use_json=T`,
##! would produce a second set of `uid`s to reconcile and a second chance for them to differ.
##!
##! Only `conn` and `ssl` get a filter, because those are the only two logs flabel parses:
##! `conn` is the flow table, `ssl` supplies `ja4` / `ja4s` / `server_name` joined on `uid`.
##! Every other log is retained as Zeek wrote it.
##!
##! Timestamps are epoch floats rather than Zeek's default ISO-8601 strings, so the parser
##! reads `ts` with `float()` and cannot introduce a timezone or a precision loss of its own.
##!
##! The JA4 fields are not named here: `zeek/foxio/ja4` adds them to `SSL::Info` as logged
##! fields, and a filter with no `$include` writes every logged field, so they appear in
##! `ssl_json.log` whenever `zeek.py` loaded that package — and are simply absent otherwise.

@load base/protocols/conn
@load base/protocols/ssl

module FlabelJSON;

export {
	## Filter name, on both streams. Distinct from Zeek's own `default` filter, which keeps
	## writing the TSV logs flabel retains.
	const filter_name = "flabel-json" &redef;

	## Log paths the filters write, without the `.log` suffix. `zeek.py` parses these and
	## then removes them from the retained output, so the names are duplicated there; they
	## are `const` here so that this file states them once.
	const conn_path = "conn_json" &redef;
	const ssl_path = "ssl_json" &redef;
}

## Writer options for the ASCII writer, read per-filter rather than globally — a global
## `LogAscii::use_json` would turn *every* log into JSON, including the ones flabel retains.
function json_config(): table[string] of string
	{
	return table(["use_json"] = "T", ["json_timestamps"] = "JSON::TS_EPOCH");
	}

event zeek_init()
	{
	Log::add_filter(Conn::LOG,
	                Log::Filter($name=filter_name, $path=conn_path, $config=json_config()));
	Log::add_filter(SSL::LOG,
	                Log::Filter($name=filter_name, $path=ssl_path, $config=json_config()));
	}
