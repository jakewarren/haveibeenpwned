package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/apex/log"
	"github.com/apex/log/handlers/cli"
	"github.com/jakewarren/haveibeenpwned/api"
	"github.com/jinzhu/now"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	app = kingpin.New("haveibeenpwned", "Un-official API client for haveibeenpwned.com.")

	debug      = app.Flag("debug", "print debug info").Short('d').Bool()
	filterDate = app.Flag("filter-date", "only print breaches released after specified date").Short('f').String()
	silent     = app.Flag("silent", "suppress response message, only display results").Short('s').Bool()
	envvar     = app.Flag("env", "environment variable to check for the HIBP API key").Default("HIBP_API_KEY").Short('e').String()
	key        = app.Flag("key", "HIBP API key").Short('k').String()

	email = app.Arg("email", "the email address to lookup.").Required().String()

	client *api.Client

	version = "(ﾉ☉ヮ⚆)ﾉ ⌒*:･ﾟ✧"
)

func main() {
	app.Version(version).VersionFlag.Short('V')
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

	if apikey, ok := os.LookupEnv(*envvar); ok {
		client = api.NewClient(apikey)
	} else {
		if len(*key) == 0 {
			log.Fatal("No API key provided")
		}

		client = api.NewClient(*key)
	}

	printBreachResults(*email)

	//sleep to respect the haveibeenpwned API rate limiting
	time.Sleep(2 * time.Second)

	printPasteResults(*email)

}

func printBreachResults(email string) {
	//query results for the email address
	breaches, err := client.LookupEmailBreaches(email)
	if err != nil {
		log.WithError(err).Errorf("error looking up breach data for %s", email)
		return
	}

	breachCount := 0
	var defResponse string

	for _, breach := range breaches {

		if *filterDate != "" {
			filterTime, err := now.Parse(*filterDate)
			if err != nil {
				log.WithError(err).Error("error parsing filter time")
			}

			releaseTime, err := time.Parse(time.RFC3339, breach.AddedDate)
			if err != nil {
				log.WithError(err).Error("error parsing released time")
			}

			if releaseTime.Before(filterTime) {
				log.Debugf("excluding %s (%s)", breach.Title, breach.AddedDate)
				continue
			}

		}
		defResponse += fmt.Sprintf("\n%s\n\tdomain:\t\t%s\n\tadded_date:\t%s\n\tbreach_date:\t%s\n", breach.Title, breach.Domain, breach.AddedDate, breach.BreachDate)
		defResponse += fmt.Sprintf("\temail_count:\t%s\n\tverified:\t%t\n", CommifyNumber(breach.PwnCount), breach.IsVerified)
		if *debug {
			defResponse += fmt.Sprintf("%#+v\n", breach)
		}

		defResponse += "\n"

		breachCount++
	}

	if !*silent {
		if *filterDate == "" {
			fmt.Printf("%d breaches returned for %s\n", breachCount, email)
		} else {
			fmt.Printf("%d breaches returned for %s (%d filtered out)\n", breachCount, email, (len(breaches) - breachCount))
		}
	} else if breachCount > 0 {
		fmt.Printf("%d breaches returned for %s (%d filtered out)\n", breachCount, email, (len(breaches) - breachCount))
	}

	fmt.Print(defResponse)
}

func printPasteResults(email string) {
	//query results for the email address
	pastes, err := client.LookupEmailPastes(email)
	if err != nil {
		log.WithError(err).Errorf("error looking up paste data for %s", email)
		return
	}

	pasteCount := 0
	var defResponse string

	for _, paste := range pastes {

		if *filterDate != "" {
			filterTime, err := now.Parse(*filterDate)
			if err != nil {
				log.WithError(err).Error("error parsing filter time")
			}

			releaseTime, err := time.Parse(time.RFC3339, paste.Date)
			if err != nil {
				log.WithError(err).Error("error parsing released time")
			}

			if releaseTime.Before(filterTime) {
				log.Debugf("excluding %s (%s)", paste.ID, paste.Date)
				continue
			}

		}
		defResponse += fmt.Sprintf("\n%s\n\ttitle:\t\t%s\n\tID:\t\t%s\n\tbreach_date:\t%s\n\temail_count:\t%s\n", paste.Source, paste.Title, paste.ID, paste.Date, CommifyNumber(paste.EmailCount))

		if *debug {
			defResponse += fmt.Sprintf("%#+v\n", paste)
		}

		pasteCount++
	}

	if !*silent {
		if *filterDate == "" {
			fmt.Printf("%d pastes returned for %s\n", pasteCount, email)
		} else {
			fmt.Printf("%d pastes returned for %s (%d filtered out)\n", pasteCount, email, (len(pastes) - pasteCount))
		}
	}

	fmt.Print(defResponse)
}

//CommifyNumber takes a number and returns a string with the number using comma separators
func CommifyNumber(n int64) string {
	in := strconv.FormatInt(n, 10)
	out := make([]byte, len(in)+(len(in)-2+int(in[0]/'0'))/3)
	if in[0] == '-' {
		in, out[0] = in[1:], '-'
	}

	for i, j, k := len(in)-1, len(out)-1, 0; ; i, j = i-1, j-1 {
		out[j] = in[i]
		if i == 0 {
			return string(out)
		}
		if k++; k == 3 {
			j, k = j-1, 0
			out[j] = ','
		}
	}
}
