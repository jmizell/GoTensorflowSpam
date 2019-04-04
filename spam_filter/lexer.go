package spam_filter

import (
	"fmt"
	"github.com/emersion/go-message"
	"github.com/glenn-brown/golang-pkg-pcre/src/pkg/pcre"
	"golang.org/x/net/html"
	"io"
	"io/ioutil"
	"log"
)

var reIPV6 = `((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?`
var reIPV4 = `(?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))(?![0-9])`
var reIP = fmt.Sprintf("(?:%s|%s)", reIPV6, reIPV4)
var reHOSTNAME = `\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(\.?|\b)`
var reIPORHOST = fmt.Sprintf("(?:%s|(?P<HOST>%s))", reIP, reHOSTNAME)
var rePOSINT = `\b(?:[1-9][0-9]*)\b`
var reUSERNAME = `[a-zA-Z0-9._-]+`
var reURIPROTO = `[A-Za-z]+(\+[A-Za-z+]+)?`
var reURIHOST = fmt.Sprintf("%s(?::%s)?", reIPORHOST, rePOSINT)
var reURIPATH = `(?:/[A-Za-z0-9$.+!*'(){},~:;=@#%_\-]*)+`
var reURIPARAM = `\?[A-Za-z0-9$.+!*'|(){},~@#%&/=:;_?\-\[\]]*`
var reURIPATHPARAM = fmt.Sprintf("%s(?:%s)?", reURIPATH, reURIPARAM)
var reURI = fmt.Sprintf("%s://(?:%s(?::[^@]*)?@)?(?:%s)?(?:%s)?", reURIPROTO, reUSERNAME, reURIHOST, reURIPATHPARAM)

var reNonwords = pcre.MustCompile(`[^\w,\.]+`, pcre.CASELESS)
var reNumbers = pcre.MustCompile(`(?<=[\s_\.,-])\d+(?=[\s_\.,-])`, pcre.CASELESS)
var reUri = pcre.MustCompile(reURI, pcre.CASELESS)


type Lexer struct {
	Keywords map[string]int
}

func (l *Lexer) TextToSequence(rfc822Message io.Reader) (interface{}, error) {

	m, err := message.Read(rfc822Message)
	if err != nil {
		return nil, err
	}

	if ip := m.Header.Get("X-Originating-Ip"); ip != "" {
		fmt.Println("DEBUG -- -- ip", ip)
	}

	var messageText string
	var messageHTML string
	if mr := m.MultipartReader(); mr != nil {
		// This is a multipart message
		log.Println("This is a multipart message containing:")
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			d, err := ioutil.ReadAll(p.Body)
			if err != nil {
				return nil, err
			}

			t, _, _ := p.Header.ContentType()
			switch t {
			case "text/html":
				messageHTML = fmt.Sprintf("%s%s", messageHTML, string(d))
			case "text/plain":
				messageText = fmt.Sprintf("%s%s", messageText, string(d))
			}
		}
	} else {



		t, _, _ := m.Header.ContentType()
		switch t {
		case "text/html":

			doc, err := html.Parse(m.Body)
			if err != nil {
				log.Fatal(err)
			}

			fmt.Println(doc.Data)

			//messageHTML = string(d)
		case "text/plain":
			d, err := ioutil.ReadAll(m.Body)
			if err != nil {
				return nil, err
			}
			messageText = string(d)
		}
	}

	subject := m.Header.Get("Subject")

	sequenceText := fmt.Sprintf("%s %s", subject, messageText)

	// remove line breaks
	// replace links with just the domain
	// re_non_word.sub(' ', text)
	// shrink whitespace
	// replace numbers with 0000
	// covert all text to lower case

	return sequenceText, nil
}