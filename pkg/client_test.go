package pkg

import (
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
