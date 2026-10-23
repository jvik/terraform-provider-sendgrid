package sendgrid

import (
	"context"
	"fmt"

	sendgrid "github.com/arslanbekov/terraform-provider-sendgrid/sdk"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSendgridDomainAuthentication() *schema.Resource {
	s := resourceSendgridDomainAuthentication().Schema

	// The data source only reads, so on-behalf-of calls do not apply.
	delete(s, "sub_user_on_behalf_of")

	for _, val := range s {
		val.Computed = true
		val.Optional = false
		val.Required = false
		val.Default = nil
		val.ValidateFunc = nil
		val.ForceNew = false
	}

	s["domain"] = &schema.Schema{
		Type:        schema.TypeString,
		Required:    true,
		Description: "The authenticated domain to look up, e.g. `example.com`.",
	}
	s["subdomain"] = &schema.Schema{
		Type:     schema.TypeString,
		Optional: true,
		Computed: true,
		Description: "The subdomain of the authenticated domain, e.g. `em1234`. " +
			"Required when the parent account has several authenticated domains for `domain`.",
	}

	return &schema.Resource{
		Description: "Looks up an authenticated domain of the parent account by domain and subdomain. " +
			"Domains created by or on behalf of subusers are not included.",
		ReadContext: dataSendgridDomainAuthenticationRead,
		Schema:      s,
	}
}

func dataSendgridDomainAuthenticationRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	c := config.NewClient("")

	domain := d.Get("domain").(string)
	subdomain := d.Get("subdomain").(string)

	domains, err := c.ListDomainAuthentications(ctx, domain)
	if err.Err != nil {
		return diag.FromErr(err.Err)
	}

	matches := filterDomainAuthentications(domains, domain, subdomain)

	switch len(matches) {
	case 0:
		return diag.Errorf("no authenticated domain found for domain %q and subdomain %q", domain, subdomain)
	case 1:
		match := matches[0]
		d.SetId(fmt.Sprint(match.ID))

		if er := setDomainAuthenticationState(d, &match); er != nil {
			return diag.FromErr(er)
		}

		return nil
	default:
		return diag.Errorf("found %d authenticated domains for domain %q, set subdomain to pick one",
			len(matches), domain)
	}
}

// filterDomainAuthentications keeps the exact domain matches; the API filter
// may be broader. An empty subdomain matches any subdomain.
func filterDomainAuthentications(
	domains []sendgrid.DomainAuthentication,
	domain string,
	subdomain string,
) []sendgrid.DomainAuthentication {
	matches := make([]sendgrid.DomainAuthentication, 0)

	for _, candidate := range domains {
		if candidate.Domain != domain {
			continue
		}

		if subdomain != "" && candidate.Subdomain != subdomain {
			continue
		}

		matches = append(matches, candidate)
	}

	return matches
}
