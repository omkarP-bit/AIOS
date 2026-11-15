package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"aios/internal/config"
)

// aiCommand launches the local planner as a child process.
//
// This is operator convenience, not an authorization path. The planner is a
// fixed, operator-installed program that can only post proposals to the core,
// and it never receives an approval token or executor access. No shell is
// involved: the question travels as one argument.
func aiCommand(settings config.Settings, args []string) int {
	fs := newFlags("ai")
	execute := fs.Bool("execute", false, "execute if the core allows it")
	asJSON := jsonMode(fs)
	noContext := fs.Bool("no-context", false, "do not attach an observation snapshot")
	apiURL := fs.String("api-url", "", "Go core base URL")
	if err := parse(fs, args); err != nil {
		return parseCode(err)
	}
	question := strings.TrimSpace(strings.Join(fs.Args(), " "))
	if question == "" {
		fmt.Fprintln(os.Stderr, `usage: aios ai QUESTION... [--execute] [--json]`)
		return 2
	}

	command, err := plannerCommand()
	if err != nil {
		fail(err)
		return 1
	}
	plannerArgs := []string{}
	if *asJSON {
		plannerArgs = append(plannerArgs, "--json")
	}
	if *execute {
		plannerArgs = append(plannerArgs, "--execute")
	}
	if *noContext {
		plannerArgs = append(plannerArgs, "--no-context")
	}
	url := *apiURL
	if url == "" {
		url = settings.APIURL
	}
	if url != "" {
		plannerArgs = append(plannerArgs, "--api-url", url)
	}
	// "--" keeps a question that starts with a dash from becoming a flag.
	plannerArgs = append(plannerArgs, "--", question)

	cmd := exec.Command(command[0], append(append([]string{}, command[1:]...), plannerArgs...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "AIOS_API_URL="+url)
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode()
		}
		fail(err)
		return 1
	}
	return 0
}

// plannerCommand finds the installed planner: AIOS_PLANNER, then `aios-ai`,
// then the module through python3 or python.
func plannerCommand() ([]string, error) {
	if custom := strings.TrimSpace(os.Getenv("AIOS_PLANNER")); custom != "" {
		return []string{custom}, nil
	}
	if path, err := exec.LookPath("aios-ai"); err == nil {
		return []string{path}, nil
	}
	for _, name := range []string{"python3", "python"} {
		if path, err := exec.LookPath(name); err == nil {
			return []string{path, "-m", "aios.ai"}, nil
		}
	}
	return nil, errors.New(
		"planner not found; run 'make install-python', or set AIOS_PLANNER to its path",
	)
}
