/*
Provide a resource to associate an authenticated domain of the parent account
with a subuser.
Example Usage
```hcl

	resource "sendgrid_domain_authentication_subuser" "default" {
		domain_id = sendgrid_domain_authentication.default.id
		username  = sendgrid_subuser.default.username
	}

```
Import
An association can be imported by the subuser username, e.g.
```hcl
$ terraform import sendgrid_domain_authentication_subuser.default username
```
*/
package sendgrid

import (
	"context"
	"fmt"
	"net/http"

	sendgrid "github.com/arslanbekov/terraform-provider-sendgrid/sdk"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceSendgridDomainAuthenticationSubuser() *schema.Resource {
	return &schema.Resource{
		Description: "Associates an authenticated domain of the parent account with a subuser, " +
			"so the subuser can send from that domain without authenticating it again. " +
			"Unlike `sub_user_on_behalf_of` on `sendgrid_domain_authentication`, " +
			"this creates no new domain and no new DNS records. " +
			"A subuser has one associated domain; the association has no update, " +
			"so changing either argument replaces it.",
		CreateContext: resourceSendgridDomainAuthenticationSubuserCreate,
		ReadContext:   resourceSendgridDomainAuthenticationSubuserRead,
		DeleteContext: resourceSendgridDomainAuthenticationSubuserDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"domain_id": {
				Type:        schema.TypeString,
				Description: "ID of the parent account's authenticated domain.",
				Required:    true,
				ForceNew:    true,
			},
			"username": {
				Type:        schema.TypeString,
				Description: "Username of the subuser the domain is associated with.",
				Required:    true,
				ForceNew:    true,
			},
			"domain": {
				Type:        schema.TypeString,
				Description: "The associated domain.",
				Computed:    true,
			},
			"subdomain": {
				Type:        schema.TypeString,
				Description: "The subdomain of the associated domain.",
				Computed:    true,
			},
		},
	}
}

func resourceSendgridDomainAuthenticationSubuserCreate(
	ctx context.Context,
	d *schema.ResourceData,
	m interface{},
) diag.Diagnostics {
	config := m.(*Config)
	c := config.NewClient("")

	domainID := d.Get("domain_id").(string)
	username := d.Get("username").(string)

	_, err := sendgrid.RetryOnRateLimit(ctx, d, func() (interface{}, sendgrid.RequestError) {
		return c.AssociateDomainAuthenticationWithSubuser(ctx, domainID, username)
	})
	if err != nil {
		return diag.FromErr(err)
	}

	// A subuser has at most one associated domain, so the username identifies
	// the association. It is also what the read and delete endpoints take.
	d.SetId(username)

	return resourceSendgridDomainAuthenticationSubuserRead(ctx, d, m)
}

func resourceSendgridDomainAuthenticationSubuserRead(
	ctx context.Context,
	d *schema.ResourceData,
	m interface{},
) diag.Diagnostics {
	config := m.(*Config)
	c := config.NewClient("")

	username := d.Id()

	auth, err := c.ReadSubuserDomainAuthentication(ctx, username)
	if err.Err != nil {
		if err.StatusCode == http.StatusNotFound {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err.Err)
	}

	// No associated domain: the association was removed outside Terraform.
	if auth.ID == 0 {
		d.SetId("")
		return nil
	}

	// A different domain_id than in the configuration is drift, and plans a
	// replacement back to the configured domain.
	//nolint:errcheck
	d.Set("domain_id", fmt.Sprint(auth.ID))
	//nolint:errcheck
	d.Set("username", username)
	//nolint:errcheck
	d.Set("domain", auth.Domain)
	//nolint:errcheck
	d.Set("subdomain", auth.Subdomain)

	return nil
}

func resourceSendgridDomainAuthenticationSubuserDelete(
	ctx context.Context,
	d *schema.ResourceData,
	m interface{},
) diag.Diagnostics {
	config := m.(*Config)
	c := config.NewClient("")

	username := d.Id()

	_, err := sendgrid.RetryOnRateLimit(ctx, d, func() (interface{}, sendgrid.RequestError) {
		return c.DisassociateDomainAuthenticationFromSubuser(ctx, username)
	})
	if err != nil {
		return diag.FromErr(err)
	}

	return nil
}
