package sendgrid

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

const subuserDomainBody = `{
	"id":123,
	"domain":"example.com",
	"subdomain":"em1234",
	"username":"parent",
	"valid":true,
	"dns":{}
}`

func TestDomainAuthenticationSubuserCreate_Success(t *testing.T) {
	var associatedUsername string

	mux := http.NewServeMux()
	mux.HandleFunc("/whitelabel/domains/123/subuser", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}

		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decoding request body: %v", err)
		}
		associatedUsername = body["username"]

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(subuserDomainBody))
	})
	mux.HandleFunc("/whitelabel/domains/subuser", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(subuserDomainBody))
	})

	server, config := setupDomainAuthenticationMockServer(mux)
	defer server.Close()

	r := resourceSendgridDomainAuthenticationSubuser()
	d := r.TestResourceData()
	_ = d.Set("domain_id", "123")
	_ = d.Set("username", "sub-one")

	diags := resourceSendgridDomainAuthenticationSubuserCreate(context.Background(), d, config)

	if diags.HasError() {
		t.Fatalf("Create() returned unexpected error: %v", diags)
	}
	if associatedUsername != "sub-one" {
		t.Errorf("POST body username = %q, want %q", associatedUsername, "sub-one")
	}
	if d.Id() != "sub-one" {
		t.Errorf("Create() id = %q, want %q", d.Id(), "sub-one")
	}
	if d.Get("domain") != "example.com" {
		t.Errorf("Create() domain = %v, want %q", d.Get("domain"), "example.com")
	}
}

func TestDomainAuthenticationSubuserRead_Success(t *testing.T) {
	var requestedUsername string

	mux := http.NewServeMux()
	mux.HandleFunc("/whitelabel/domains/subuser", func(w http.ResponseWriter, r *http.Request) {
		requestedUsername = r.URL.Query().Get("username")

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(subuserDomainBody))
	})

	server, config := setupDomainAuthenticationMockServer(mux)
	defer server.Close()

	r := resourceSendgridDomainAuthenticationSubuser()
	d := r.TestResourceData()
	d.SetId("sub-one")

	diags := resourceSendgridDomainAuthenticationSubuserRead(context.Background(), d, config)

	if diags.HasError() {
		t.Fatalf("Read() returned unexpected error: %v", diags)
	}
	if requestedUsername != "sub-one" {
		t.Errorf("username query = %q, want %q", requestedUsername, "sub-one")
	}
	// Set on import, where only the id is known.
	if d.Get("domain_id") != "123" {
		t.Errorf("Read() domain_id = %v, want %q", d.Get("domain_id"), "123")
	}
	if d.Get("username") != "sub-one" {
		t.Errorf("Read() username = %v, want %q", d.Get("username"), "sub-one")
	}
	if d.Get("subdomain") != "em1234" {
		t.Errorf("Read() subdomain = %v, want %q", d.Get("subdomain"), "em1234")
	}
}

func TestDomainAuthenticationSubuserRead_Gone(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{"not found", http.StatusNotFound, `{"errors":[{"message":"not found"}]}`},
		{"empty object", http.StatusOK, `{}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/whitelabel/domains/subuser", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			})

			server, config := setupDomainAuthenticationMockServer(mux)
			defer server.Close()

			r := resourceSendgridDomainAuthenticationSubuser()
			d := r.TestResourceData()
			d.SetId("sub-one")

			diags := resourceSendgridDomainAuthenticationSubuserRead(context.Background(), d, config)

			if diags.HasError() {
				t.Fatalf("Read() returned unexpected error: %v", diags)
			}
			if d.Id() != "" {
				t.Errorf("Read() should clear the id, got %q", d.Id())
			}
		})
	}
}

func TestDomainAuthenticationSubuserDelete(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		wantErr bool
	}{
		{"deleted", http.StatusNoContent, false},
		{"already gone", http.StatusNotFound, false},
		{"server error", http.StatusBadRequest, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requestedUsername string

			mux := http.NewServeMux()
			mux.HandleFunc("/whitelabel/domains/subuser", func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete {
					t.Errorf("method = %s, want DELETE", r.Method)
				}
				requestedUsername = r.URL.Query().Get("username")
				w.WriteHeader(tt.status)
			})

			server, config := setupDomainAuthenticationMockServer(mux)
			defer server.Close()

			r := resourceSendgridDomainAuthenticationSubuser()
			d := r.TestResourceData()
			d.SetId("sub-one")

			diags := resourceSendgridDomainAuthenticationSubuserDelete(context.Background(), d, config)

			if diags.HasError() != tt.wantErr {
				t.Fatalf("Delete() error = %v, wantErr %v", diags, tt.wantErr)
			}
			if requestedUsername != "sub-one" {
				t.Errorf("username query = %q, want %q", requestedUsername, "sub-one")
			}
		})
	}
}

func TestDomainAuthenticationSubuserResourceSchema(t *testing.T) {
	r := resourceSendgridDomainAuthenticationSubuser()

	for _, field := range []string{"domain_id", "username"} {
		s, ok := r.Schema[field]
		if !ok {
			t.Fatalf("schema missing field %q", field)
		}
		if !s.Required || !s.ForceNew {
			t.Errorf("%s should be Required and ForceNew", field)
		}
	}

	if r.UpdateContext != nil {
		t.Error("resource should have no update")
	}
	if r.Importer == nil {
		t.Error("resource should have an Importer configured")
	}
}

func TestDomainAuthenticationDataSourceRead(t *testing.T) {
	listBody := `[
		{"id":1,"domain":"example.com","subdomain":"em1111","valid":true,"dns":{}},
		{"id":2,"domain":"example.com","subdomain":"em2222","valid":false,"dns":{}},
		{"id":3,"domain":"other.example.com","subdomain":"em3333","valid":true,"dns":{}}
	]`

	tests := []struct {
		name      string
		subdomain string
		wantID    string
		wantErr   bool
	}{
		{"by subdomain", "em2222", "2", false},
		{"ambiguous without subdomain", "", "", true},
		{"no match", "em9999", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var query map[string][]string

			mux := http.NewServeMux()
			mux.HandleFunc("/whitelabel/domains", func(w http.ResponseWriter, r *http.Request) {
				query = r.URL.Query()

				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(listBody))
			})

			server, config := setupDomainAuthenticationMockServer(mux)
			defer server.Close()

			r := dataSendgridDomainAuthentication()
			d := r.TestResourceData()
			_ = d.Set("domain", "example.com")
			_ = d.Set("subdomain", tt.subdomain)

			diags := dataSendgridDomainAuthenticationRead(context.Background(), d, config)

			if diags.HasError() != tt.wantErr {
				t.Fatalf("Read() error = %v, wantErr %v", diags, tt.wantErr)
			}
			if d.Id() != tt.wantID {
				t.Errorf("Read() id = %q, want %q", d.Id(), tt.wantID)
			}
			if query["exclude_subusers"][0] != "true" || query["domain"][0] != "example.com" {
				t.Errorf("unexpected query: %v", query)
			}
		})
	}
}
