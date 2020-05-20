package pkg

import (
	"encoding/xml"
	"testing"
)

func TestSignature(t *testing.T) {
	s, err := generateClientData(clientData{Token: "1"})
	if err != nil {
		t.Errorf("Signature is wrong: %s", err)
	}

	expected := "c2Vzc2lvbj0mZGV2aWNlX2luZm89UEdGblpXNTBYMmx1Wm04K1BIUjVjR1UrYzNSaGJtUmhiRzl1WlR3dmRIbHdaVDQ4ZG1WeWMybHZiajR5TGpBOEwzWmxjbk5wYjI0K1BIQnNZWFJtYjNKdFBreHBiblY0UEM5d2JHRjBabTl5YlQ0OFkzQjFQbmcyTkR3dlkzQjFQanhxWVhaaGMyTnlhWEIwUG01dlBDOXFZWFpoYzJOeWFYQjBQanhoWTNScGRtVjRQbTV2UEM5aFkzUnBkbVY0UGp4d2JIVm5hVzQrYm04OEwzQnNkV2RwYmo0OGJHRnVaR2x1WjNWeWFUNHZQQzlzWVc1a2FXNW5kWEpwUGp4c2IyTnJaV1J0YjJSbFBtNXZQQzlzYjJOclpXUnRiMlJsUGp4b2IzTjBibUZ0WlQ1a1IxWjZaRUU5UFR3dmFHOXpkRzVoYldVK1BHRndjRjlwWkQ0OEwyRndjRjlwWkQ0OEwyRm5aVzUwWDJsdVptOCsmYWdlbnRfcmVzdWx0PSZ0b2tlbj0xJnNpZ25hdHVyZT00c1krcFFkM3pyUTVjMkZsNUJ3a0JnPT0="
	if s != expected {
		t.Errorf("Client data doesn't correspond to expected: %s", s)
	}
}

func TestUnmarshal(t *testing.T) {
	// parse https://f5.com/pre/config.php
	b := []byte(`<PROFILE VERSION="2.0"><SERVERS><SITEM><ADDRESS>https://f5-1.com</ADDRESS><ALIAS>One</ALIAS></SITEM><SITEM><ADDRESS>https://f5-2.com</ADDRESS><ALIAS>Two</ALIAS></SITEM></SERVERS><SESSION LIMITED="YES"><SAVEONEXIT>YES</SAVEONEXIT><SAVEPASSWORDS>NO</SAVEPASSWORDS><REUSEWINLOGONCREDS>NO</REUSEWINLOGONCREDS><REUSEWINLOGONSESSION>NO</REUSEWINLOGONSESSION><PASSWORD_POLICY><MODE>DISK</MODE><TIMEOUT>240</TIMEOUT></PASSWORD_POLICY><UPDATE><MODE>YES</MODE></UPDATE></SESSION><LOCATIONS><CORPORATE><DNSSUFFIX>corp.int</DNSSUFFIX><DNSSUFFIX>corp</DNSSUFFIX></CORPORATE></LOCATIONS></PROFILE>`)
	var s preConfigProfile
	if err := xml.Unmarshal(b, &s); err != nil {
		t.Errorf("failed to unmarshal a response: %s", err)
	}
}
