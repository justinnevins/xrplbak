package main

import (
	"errors"

	"github.com/justinnevins/xrplbak/internal/export"
)

// cmdExport prints every backup file in one folder as a single checked
// archive on stdout. It is the host half of an off-host copy: a sudo rule
// can name this command with these exact arguments, so a login user can
// fetch the files from a root-only folder without a root shell. It reads
// only, and it prints nothing until every entry in the folder passed.
func cmdExport(args []string) error {
	fs := newFlags("export", "print every backup file in a folder as one archive, to copy off this host")
	out := fs.String("out", "", "the backup folder: the --out of backup --submit")
	if err := fs.Parse(args); err != nil {
		return parseError(err)
	}
	if fs.NArg() > 0 {
		return fail(exitUsage, "unexpected argument %q; export takes --out DIR and nothing else", fs.Arg(0))
	}
	if *out == "" {
		return fail(exitUsage, "export needs --out DIR, the folder backup --submit wrote the bundle and dump to")
	}
	archive, _, err := export.Archive(*out)
	var refused *export.RefusedError
	switch {
	case errors.Is(err, export.ErrNoBackups):
		return fail(exitIncomplete, "%v", err)
	case errors.As(err, &refused):
		return fail(exitRefused, "%v", err)
	case err != nil:
		return fail(exitUsage, "%v", err)
	}
	if _, err := stdout.Write(export.Frame(archive)); err != nil {
		return fail(exitWrite, "%v", err)
	}
	return nil
}
