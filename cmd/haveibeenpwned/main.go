package main

import (
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
	"github.com/apex/log"
	"github.com/apex/log/handlers/cli"
	"github.com/MasenkoHa/haveibeenpwned"
	"time"
)

var (
	app = kingpin.New("haveibeenpwned", "Un-official API client for haveibeenpwned.com.")

	debug      = app.Flag("debug", "print debug info").Short('d').Bool()
	filterDate = app.Flag("filter-date", "only print breaches released after specified date").Short('f').String()
	silent     = app.Flag("silent", "suppress response message, only display results").Short('s').Bool()

	email = app.Arg("email", "the email address to lookup.").Required().String()
)
func main() {
	app.Version("0.1.0").VersionFlag.Short('V')
	app.HelpFlag.Short('h')
	app.UsageTemplate(kingpin.SeparateOptionalFlagsUsageTemplate)
	kingpin.MustParse(app.Parse(os.Args[1:]))

	log.SetHandler(cli.New(os.Stderr))
	log.SetLevel(log.ErrorLevel)

	if *silent {
		//turn off errors
		log.SetLevel(log.FatalLevel)
	}

	if *debug {
		log.SetLevel(log.DebugLevel)
	}
haveibeenpwned.PrintBreachResults(*email, *filterDate, *debug, *silent)
time.Sleep(3 * time.Second)
haveibeenpwned.PrintPasteResults(*email, *filterDate, *debug, *silent)
}