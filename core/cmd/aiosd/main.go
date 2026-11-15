// Command aiosd runs the control API without the CLI.
package main

import (
	"fmt"
	"os"

	"aios/internal/api"
	"aios/internal/config"
	"aios/internal/runtime"
)

func main() {
	settings := config.Load()
	rt, err := runtime.New(settings)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Printf("AIOS control API listening on %s:%d\n", settings.APIHost, settings.APIPort)
	if err := api.New(rt).ListenAndServe(settings); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
