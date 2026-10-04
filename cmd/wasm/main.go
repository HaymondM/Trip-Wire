//go:build js && wasm

// Command wasm exposes the engine to JavaScript as a global
// tripWireAnalyze(segmentsJSON) -> reportJSON function.
package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/HaymondM/Trip-Wire/engine"
)

func errorJSON(msg string) string {
	out, _ := json.Marshal(map[string]string{"error": msg})
	return string(out)
}

func analyze(_ js.Value, args []js.Value) any {
	if len(args) != 1 || args[0].Type() != js.TypeString {
		return errorJSON("tripWireAnalyze expects one JSON string argument")
	}
	var segments []engine.Segment
	if err := json.Unmarshal([]byte(args[0].String()), &segments); err != nil {
		return errorJSON("invalid segments JSON: " + err.Error())
	}
	out, err := json.Marshal(engine.Analyze(segments))
	if err != nil {
		return errorJSON(err.Error())
	}
	return string(out)
}

func main() {
	js.Global().Set("tripWireAnalyze", js.FuncOf(analyze))
	select {}
}
