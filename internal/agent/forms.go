package agent

import (
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// FormInput adalah satu field di dalam form HTML.
type FormInput struct {
	Name  string
	Type  string // text, hidden, file, password, ...
	Value string
}

// Form adalah representasi minimal form HTML untuk check CSRF & file-upload.
type Form struct {
	PageURL string // halaman tempat form ditemukan
	Action  string // URL absolut tujuan submit
	Method  string // GET / POST (default GET)
	EncType string
	Inputs  []FormInput
}

// HasFile melaporkan apakah form punya input type=file.
func (f Form) HasFile() bool {
	for _, in := range f.Inputs {
		if strings.EqualFold(in.Type, "file") {
			return true
		}
	}
	return false
}

var csrfTokenHints = []string{"csrf", "token", "authenticity", "_nonce", "verification"}

// HasCSRFToken melaporkan apakah form memuat field yang tampaknya token anti-CSRF.
func (f Form) HasCSRFToken() bool {
	for _, in := range f.Inputs {
		n := strings.ToLower(in.Name)
		for _, h := range csrfTokenHints {
			if strings.Contains(n, h) {
				return true
			}
		}
	}
	return false
}

// ParseForms mengekstrak semua form dari HTML, menyelesaikan action relatif
// terhadap URL halaman.
func ParseForms(pageURL, body string) []Form {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}
	base, _ := url.Parse(pageURL)
	var forms []Form
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			f := Form{PageURL: pageURL, Method: "GET"}
			rawAction := ""
			for _, a := range n.Attr {
				switch strings.ToLower(a.Key) {
				case "action":
					rawAction = a.Val
				case "method":
					f.Method = strings.ToUpper(a.Val)
				case "enctype":
					f.EncType = a.Val
				}
			}
			if base != nil {
				if ref, err := base.Parse(rawAction); err == nil {
					f.Action = ref.String()
				}
			}
			if f.Action == "" {
				f.Action = pageURL
			}
			collectInputs(n, &f)
			forms = append(forms, f)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return forms
}

func collectInputs(n *html.Node, f *Form) {
	if n.Type == html.ElementNode && (n.Data == "input" || n.Data == "textarea" || n.Data == "select") {
		in := FormInput{Type: "text"}
		for _, a := range n.Attr {
			switch strings.ToLower(a.Key) {
			case "name":
				in.Name = a.Val
			case "type":
				in.Type = a.Val
			case "value":
				in.Value = a.Val
			}
		}
		if in.Name != "" {
			f.Inputs = append(f.Inputs, in)
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		collectInputs(c, f)
	}
}
